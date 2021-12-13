package site.idong;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import io.github.itning.retry.Retryer;
import io.github.itning.retry.RetryerBuilder;
import io.github.itning.retry.strategy.stop.StopStrategies;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.cookie.BasicClientCookie;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Application {
    @Parameter(names={"--user"},help = true,required =true ,description = "用户登录信息（JSON格式）")
    String user;
    @Parameter(names = "--help", help = true,description = "帮助")
    private boolean help;
    private static final Logger log = LoggerFactory.getLogger(Application.class);
    private static String ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36 Edg/96.0.1054.43";
    protected static String initVector = "encryptionIntVec";
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args) {
        Application main = new Application();
        JCommander jct = JCommander.newBuilder()
                .addObject(main)
                .build();
        jct.setProgramName("河海大学健康上报系统");
        try {
            jct.parse(args);
            // 提供帮助说明
            if (main.help) {
                jct.usage();
                return;
            }
            main.run();
        }
        catch (ParameterException parameterException ){
            // 为了方便使用，同时输出exception的message
            System.out.printf(parameterException.toString()+"\r\n");
            jct.usage();
        }
    }
    public void run() {
        Boolean isAllSuccess = true;
        try {
            JSONArray users = JSON.parseArray(user);
            Iterator iter = users.iterator();
            while (iter.hasNext()) {

                JSONObject _user = (JSONObject) iter.next();
                log.info("解析成功，用户名：" + _user.getString("username"));
                Retryer<Integer> retryer = RetryerBuilder.<Integer>newBuilder()
                        .retryIfResult(result -> result == -1)
                        // 设置最大执行次数3次
                        .withStopStrategy(StopStrategies.stopAfterAttempt(3)).build();
                try {
                    retryer.call(() -> doReport(_user.getString("username"), _user.getString("password")));
                } catch (Exception e) {
                    log.error("重试结束，异常：" + e.getMessage());
                    isAllSuccess = false;
                }
            }
            if (isAllSuccess != Boolean.TRUE) {
                throw new Exception("部分打卡未成功");
            }
        } catch (Exception e){
            System.exit(0);
        }
        System.exit(0);
    }
    protected static String encrypt(String value,String key) {
        value = RandomStringUtils.randomAlphabetic(64)+value;
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            log.error(ex.toString());
        }
        return null;
    }
    protected static int doReport(String username, String password){
        final ExecutorService exec = Executors.newFixedThreadPool(1);
        Callable<Integer> call = new Callable<Integer>() {
            @Override
            public Integer call() throws Exception {
                Code code = newReport(username,password);
                if(code == Code.CHANGE_EHHU) {
                    log.info("尝试切换到E河海接口打卡");
                    code = oldReport(username, password);
                    if(code == Code.EXIT){
                        log.error("打卡失败");
                        return 0;
                    }
                    if(code == Code.RETRY){
                        log.error("准备重试");
                        return -1;
                    }
                    else if(code == Code.OK){
                        log.info("打卡成功");
                        return 0;
                    }
                }
                else if(code == Code.EXIT){
                    log.error("打卡失败");
                    return 0;
                }
                if(code == Code.RETRY){
                    log.error("准备重试");
                    return -1;
                }
                else if(code == Code.OK){
                    log.info("打卡成功");
                    return 0;
                }
                return 0;
            }
        };
        Future<Integer> future = exec.submit(call);
        try {
            return future.get(1000 * 180, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            exec.shutdownNow();
            return -1;
        } catch (InterruptedException e) {
            return -1;
        } catch (ExecutionException e) {
            return -1;
        }
    }
    public static List<String> regEx(String patten, String textArea) {
        String pattern = patten;
        Pattern compile = Pattern.compile(pattern);
        Matcher matcher = compile.matcher(textArea);
        List<String> targetList = new ArrayList<String>();
        while (matcher.find()) {
            String substring = textArea.substring(matcher.start(), matcher.end());
            targetList.add(substring);
        }
        return targetList;
    }
    private static Code oldReport(String username, String password) {
        // 全局请求设置
        RequestConfig globalConfig = RequestConfig.custom().setCookieSpec(StandardCookieSpec.STRICT).setCircularRedirectsAllowed(true).build();
        // 创建cookie store的本地实例
        CookieStore cookieStore =  new BasicCookieStore();
        // 创建HttpClient上下文
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);

        // 创建一个HttpClient
        CloseableHttpClient httpClient = HttpClients.custom().setDefaultRequestConfig(globalConfig)
                .setDefaultCookieStore(cookieStore).build();

        CloseableHttpResponse res =  null ;
        log.info("正在使用E河海打卡");
        HttpPost httpPost = new HttpPost("http://mids.hhu.edu.cn/_ids_mobile/login18_9");
        List<NameValuePair> nvps = new ArrayList<>();
        nvps.add(new BasicNameValuePair("username", username));
        nvps.add(new BasicNameValuePair("password", password));
        httpPost.setEntity(new UrlEncodedFormEntity(nvps));
        try {
            res = httpClient.execute(httpPost,context);
            if(res.getFirstHeader("loginErrCode") != null){
                log.error("用户名或密码错误，错误代码："+res.getFirstHeader("loginErrCode").getValue());
                return Code.EXIT;
            }
            else{

                if(res.getFirstHeader("ssoCookie") != null) {
                    JSONArray cookieArr = JSONArray.parseArray(res.getFirstHeader("ssoCookie").getValue());
                    Iterator<Object> it   = cookieArr.iterator();
                    while (it.hasNext()) {
                        JSONObject jsonObj = (JSONObject) it.next();
                        BasicClientCookie cookie = new BasicClientCookie(jsonObj.getString("cookieName"), jsonObj.getString("cookieValue"));
                        cookie.setDomain("form.hhu.edu.cn");
                        cookieStore.addCookie(cookie);
                    }
                    log.info("E河海登录成功");
                    res.close();
                    HttpGet httpGet = new HttpGet("http://form.hhu.edu.cn/pdc/form/list");
                    res = httpClient.execute(httpGet,context);
                    String page = null;
                    try {
                        page = EntityUtils.toString(res.getEntity());
                    } catch (ParseException e) {
                        log.error(e.toString());
                        return Code.RETRY;
                    }
                    if(page.contains("健康打卡")){
                        if(page.contains("本科生")){
                            res.close();
                            log.info("form.hhu.edu.cn识别成功，身份：本科生");
                            httpGet = new HttpGet("http://form.hhu.edu.cn/pdc/formDesignApi/S/gUTwwojq");
                            res = httpClient.execute(httpGet,context);
                            try {
                                page = EntityUtils.toString(res.getEntity());
                            } catch (ParseException e) {
                                log.error(e.toString());
                                return Code.RETRY;
                            }
                            if(page.contains("未知错误")){
                                log.error("form.hhu.edu.cn系统异常");
                                return Code.RETRY;
                            }
                            String wid = regEx("(?<=_selfFormWid = \\')(.*?)(?=\\')", page).get(0);
                            String uid = regEx("(?<=_userId = \\')(.*?)(?=\\')", page).get(0);
                            String fillDetail = regEx("(?<=fillDetail = )(.*?)(?=\\;)", page).get(0);
                            String json = "{\"XGH_336526\": \"学号\",\"XM_1474\": \"姓名\",\"SFZJH_859173\": \"身份证号\",\"SELECT_941320\": \"学院\",\"SELECT_459666\": \"年级\",\"SELECT_814855\": \"专业\",\"SELECT_525884\": \"班级\",\"SELECT_125597\": \"宿舍楼\",\"TEXT_950231\": \"宿舍号\",\"TEXT_937296\": \"手机号\",\"RADIO_6555\": \"您的体温情况？\",\"RADIO_535015\": \"您今天是否在校？\",\"RADIO_891359\": \"本人健康情况？\",\"RADIO_372002\": \"同住人健康情况？\",\"RADIO_618691\": \"本人及同住人14天内是否有中高风险地区旅居史或接触过中高风险地区人员？\"}";
                            JSONObject col = JSON.parseObject(json);
                            JSONArray fills = JSON.parseArray(fillDetail);
                            JSONObject fill = (JSONObject) fills.get(0);
                            SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd");
                            Date date = new Date(System.currentTimeMillis());

                            Iterator iter = col.entrySet().iterator();
                            List<NameValuePair> post = new ArrayList<>();
                            post.add(new BasicNameValuePair("DATETIME_CYCLE", formatter.format(date)));
                            while (iter.hasNext()) {
                                Map.Entry entry = (Map.Entry) iter.next();
                                post.add(new BasicNameValuePair(entry.getKey().toString(), fill.getString(entry.getKey().toString())));
                            }
                            httpPost = new HttpPost("http://form.hhu.edu.cn/pdc/formDesignApi/dataFormSave?wid="+wid+"&userId="+uid);
                            httpPost.setEntity(new UrlEncodedFormEntity(post, StandardCharsets.UTF_8));
                            res = httpClient.execute(httpPost,context);
                            try {
                                if(EntityUtils.toString(res.getEntity()).equals("{\"result\":true}")){
                                    log.info("打卡成功");
                                    iter = col.entrySet().iterator();
                                    while (iter.hasNext()) {
                                        Map.Entry entry = (Map.Entry) iter.next();
                                        log.info(entry.getValue()+":"+fill.getString(entry.getKey().toString()));
                                    }
                                    return Code.OK;
                                }
                                else{
                                    log.error("打卡失败");
                                    return Code.RETRY;
                                }
                            } catch (ParseException e) {
                                log.error(e.toString());
                                return Code.RETRY;
                            }
                        }
                        else if(page.contains("研究生")){
                            res.close();
                            log.info("form.hhu.edu.cn识别成功，身份：研究生");
                            httpGet = new HttpGet("http://form.hhu.edu.cn/pdc/formDesignApi/S/xznuPIjG");
                            res = httpClient.execute(httpGet,context);
                            try {
                                page = EntityUtils.toString(res.getEntity());
                            } catch (ParseException e) {
                                log.error(e.toString());
                                return Code.RETRY;
                            }
                            if(page.contains("未知错误")){
                                log.error("form.hhu.edu.cn系统异常");
                                return Code.RETRY;
                            }
                            String wid = regEx("(?<=_selfFormWid = \\')(.*?)(?=\\')", page).get(0);
                            String uid = regEx("(?<=_userId = \\')(.*?)(?=\\')", page).get(0);
                            String fillDetail = regEx("(?<=fillDetail = )(.*?)(?=\\;)", page).get(0);
                            String json = "{\"XGH_566872\": \"学号\",\"XM_140773\": \"姓名\",\"SFZJH_402404\": \"身份证号\",\"SZDW_439708\": \"学院\",\"ZY_878153\": \"专业\",\"GDXW_926421\": \"攻读学位\",\"DSNAME_606453\":\"导师\",\"PYLB_253720\": \"培养类别\",\"SELECT_172548\": \"宿舍楼\",\"TEXT_91454\": \"宿舍号\",\"TEXT_24613\": \"手机号\",\"TEXT_826040\": \"紧急联系人电话\",\"RADIO_799044\": \"您的体温情况？\",\"RADIO_384811\": \"您今天是否在校？\",\"RADIO_907280\": \"本人健康情况？\",\"RADIO_716001\": \"同住人健康情况？\",\"RADIO_248990\": \"本人及同住人14天内是否有中高风险地区旅居史或接触过中高风险地区人员？\"}";
                            JSONObject col = JSON.parseObject(json);
                            JSONArray fills = JSON.parseArray(fillDetail);
                            JSONObject fill = (JSONObject) fills.get(0);
                            SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd");
                            Date date = new Date(System.currentTimeMillis());

                            Iterator iter = col.entrySet().iterator();
                            List<NameValuePair> post = new ArrayList<>();
                            post.add(new BasicNameValuePair("DATETIME_CYCLE", formatter.format(date)));
                            while (iter.hasNext()) {
                                Map.Entry entry = (Map.Entry) iter.next();
                                post.add(new BasicNameValuePair(entry.getKey().toString(), fill.getString(entry.getKey().toString())));
                            }
                            System.out.println(post);
                            httpPost = new HttpPost("http://form.hhu.edu.cn/pdc/formDesignApi/dataFormSave?wid="+wid+"&userId="+uid);
                            httpPost.setEntity(new UrlEncodedFormEntity(post, StandardCharsets.UTF_8));
                            res = httpClient.execute(httpPost,context);
                            try {
                                if(EntityUtils.toString(res.getEntity()).equals("{\"result\":true}")){
                                    log.info("打卡成功");
                                    iter = col.entrySet().iterator();
                                    while (iter.hasNext()) {
                                        Map.Entry entry = (Map.Entry) iter.next();
                                        log.info(entry.getValue()+":"+fill.getString(entry.getKey().toString()));
                                    }
                                    return Code.OK;
                                }
                                else{
                                    log.error("打卡失败");
                                    return Code.RETRY;
                                }
                            } catch (ParseException e) {
                                log.error(e.toString());
                                return Code.RETRY;
                            }
                        }
                        else{
                            res.close();
                            log.error("form.hhu.edu.cn识别失败，身份：未知");
                            return Code.RETRY;
                        }
                    }
                    else{
                        res.close();
                        log.error("打卡页面解析失败！");
                        return Code.RETRY;
                    }
                }
                else{
                    log.error("远程服务器异常");
                    return Code.RETRY;
                }
            }

        } catch (IOException e) {
            log.error(e.toString());
            return Code.EXIT;
        }
    }
    private static Code newReport(String username, String password) {
        if(password.matches("[0-9]+")){
            log.warn("密码为弱密码，切换到E河海接口");
            return Code.CHANGE_EHHU;
        }
        else{

            // 全局请求设置
            RequestConfig globalConfig = RequestConfig.custom().setCookieSpec(StandardCookieSpec.STRICT).setCircularRedirectsAllowed(true).build();
            // 创建cookie store的本地实例
            CookieStore cookieStore =  new BasicCookieStore();
            // 创建HttpClient上下文
            HttpClientContext context = HttpClientContext.create();
            context.setCookieStore(cookieStore);

            // 创建一个HttpClient
            CloseableHttpClient httpClient = HttpClients.custom().setDefaultRequestConfig(globalConfig)
                    .setDefaultCookieStore(cookieStore).build();

            CloseableHttpResponse res =  null ;

            HttpGet httpGet = new HttpGet("http://authserver.hhu.edu.cn/authserver/needCaptcha.html?username="+username+"&pwdEncrypt2=pwdEncryptSalt&_=1630893279471");
            try {
                res = httpClient.execute(httpGet,context);
                try {
                    if(EntityUtils.toString(res.getEntity()).equals("true")){
                        res.close();
                        log.warn("该用户需输入验证码方可登录新版门户，切换到E河海打卡接口");
                        return Code.CHANGE_EHHU;
                    }
                    else{
                        res.close();
                        log.info("正在使用新版门户打卡");
                        httpGet = new HttpGet("http://authserver.hhu.edu.cn/authserver/login");
                        res = httpClient.execute(httpGet,context);
                        Document document = Jsoup.parse(EntityUtils.toString(res.getEntity()));
                        res.close();
                        String lt = Objects.requireNonNull(Objects.requireNonNull(document.getElementById("casLoginForm")).getElementsByAttributeValue("name", "lt").first()).attr("value");
                        String execution = Objects.requireNonNull(Objects.requireNonNull(document.getElementById("casLoginForm")).getElementsByAttributeValue("name", "execution").first()).attr("value");
                        String _eventId = Objects.requireNonNull(Objects.requireNonNull(document.getElementById("casLoginForm")).getElementsByAttributeValue("name", "_eventId").first()).attr("value");
                        String dllt = Objects.requireNonNull(Objects.requireNonNull(document.getElementById("casLoginForm")).getElementsByAttributeValue("name", "dllt").first()).attr("value");
                        String rmShown = Objects.requireNonNull(Objects.requireNonNull(document.getElementById("casLoginForm")).getElementsByAttributeValue("name", "rmShown").first()).attr("value");
                        String pwdDefaultEncryptSalt = Objects.requireNonNull(Objects.requireNonNull(document.getElementById("casLoginForm")).getElementById("pwdDefaultEncryptSalt")).attr("value");
                        String encrypt = encrypt(password,pwdDefaultEncryptSalt);
                        if(encrypt == null){
                            log.error("密码加密失败，切换到E河海打卡接口");
                            return Code.CHANGE_EHHU;
                        }
                        else{
                            HttpPost httpPost = new HttpPost("http://authserver.hhu.edu.cn/authserver/login");
                            List<NameValuePair> nvps = new ArrayList<>();
                            nvps.add(new BasicNameValuePair("username", username));
                            nvps.add(new BasicNameValuePair("password", encrypt));
                            nvps.add(new BasicNameValuePair("lt", lt));
                            nvps.add(new BasicNameValuePair("dllt", dllt));
                            nvps.add(new BasicNameValuePair("execution", execution));
                            nvps.add(new BasicNameValuePair("_eventId", _eventId));
                            nvps.add(new BasicNameValuePair("rmShown", rmShown));
                            httpPost.setEntity(new UrlEncodedFormEntity(nvps));
                            res = httpClient.execute(httpPost,context);
                            String url ;
                            if(context.getRedirectLocations().size() >= 1){
                                url = context.getRedirectLocations().get(0).toString();
                            }
                            else{
                                url = "http://authserver.hhu.edu.cn/authserver/login";
                            }
                            if(url.contains("http://authserver.hhu.edu.cn/authserver/index.do")){
                                res.close();
                                log.info("新版门户登陆成功！");
                                httpGet = new HttpGet("http://dailyreport.hhu.edu.cn/pdc/form/list");
                                res = httpClient.execute(httpGet,context);
                                String page = EntityUtils.toString(res.getEntity());
                                if(page.contains("健康打卡")){
                                    if(page.contains("本科生")){
                                        res.close();
                                        log.info("dailyreport.hhu.edu.cn识别成功，身份：本科生");
                                        httpGet = new HttpGet("http://dailyreport.hhu.edu.cn/pdc/formDesignApi/S/gUTwwojq");
                                        res = httpClient.execute(httpGet,context);
                                        page = EntityUtils.toString(res.getEntity());
                                        if(page.contains("未知错误")){
                                            log.error("dailyreport.hhu.edu.cn系统异常，尝试切换");
                                            return Code.CHANGE_EHHU;
                                        }
                                        String wid = regEx("(?<=_selfFormWid = \\')(.*?)(?=\\')", page).get(0);
                                        String uid = regEx("(?<=_userId = \\')(.*?)(?=\\')", page).get(0);
                                        String fillDetail = regEx("(?<=fillDetail = )(.*?)(?=\\;)", page).get(0);
                                        String json = "{\"XGH_336526\": \"学号\",\"XM_1474\": \"姓名\",\"SFZJH_859173\": \"身份证号\",\"SELECT_941320\": \"学院\",\"SELECT_459666\": \"年级\",\"SELECT_814855\": \"专业\",\"SELECT_525884\": \"班级\",\"SELECT_125597\": \"宿舍楼\",\"TEXT_950231\": \"宿舍号\",\"TEXT_937296\": \"手机号\",\"RADIO_6555\": \"您的体温情况？\",\"RADIO_535015\": \"您今天是否在校？\",\"RADIO_891359\": \"本人健康情况？\",\"RADIO_372002\": \"同住人健康情况？\",\"RADIO_618691\": \"本人及同住人14天内是否有中高风险地区旅居史或接触过中高风险地区人员？\"}";
                                        JSONObject col = JSON.parseObject(json);
                                        JSONArray fills = JSON.parseArray(fillDetail);
                                        JSONObject fill = (JSONObject) fills.get(0);
                                        SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd");
                                        Date date = new Date(System.currentTimeMillis());

                                        Iterator iter = col.entrySet().iterator();
                                        List<NameValuePair> post = new ArrayList<>();
                                        post.add(new BasicNameValuePair("DATETIME_CYCLE", formatter.format(date)));
                                        while (iter.hasNext()) {
                                            Map.Entry entry = (Map.Entry) iter.next();
                                            post.add(new BasicNameValuePair(entry.getKey().toString(), fill.getString(entry.getKey().toString())));
                                        }
                                        httpPost = new HttpPost("http://dailyreport.hhu.edu.cn/pdc/formDesignApi/dataFormSave?wid="+wid+"&userId="+uid);
                                        httpPost.setEntity(new UrlEncodedFormEntity(post, StandardCharsets.UTF_8));
                                        res = httpClient.execute(httpPost,context);
                                        if(EntityUtils.toString(res.getEntity()).equals("{\"result\":true}")){
                                            log.info("打卡成功");
                                            iter = col.entrySet().iterator();
                                            while (iter.hasNext()) {
                                                Map.Entry entry = (Map.Entry) iter.next();
                                                log.info(entry.getValue()+":"+fill.getString(entry.getKey().toString()));
                                            }
                                            return Code.OK;
                                        }
                                        else{
                                            log.error("打卡失败");
                                            return Code.RETRY;
                                        }
                                    }
                                    else if(page.contains("研究生")){
                                        res.close();
                                        log.info("dailyreport.hhu.edu.cn识别成功，身份：研究生");
                                        httpGet = new HttpGet("http://dailyreport.hhu.edu.cn/pdc/formDesignApi/S/xznuPIjG");
                                        res = httpClient.execute(httpGet,context);
                                        page = EntityUtils.toString(res.getEntity());
                                        if(page.contains("未知错误")){
                                            log.error("dailyreport.hhu.edu.cn系统异常，尝试切换");
                                            return Code.CHANGE_EHHU;
                                        }
                                        String wid = regEx("(?<=_selfFormWid = \\')(.*?)(?=\\')", page).get(0);
                                        String uid = regEx("(?<=_userId = \\')(.*?)(?=\\')", page).get(0);
                                        String fillDetail = regEx("(?<=fillDetail = )(.*?)(?=\\;)", page).get(0);
                                        String json = "{\"XGH_566872\": \"学号\",\"XM_140773\": \"姓名\",\"SFZJH_402404\": \"身份证号\",\"SZDW_439708\": \"学院\",\"ZY_878153\": \"专业\",\"GDXW_926421\": \"攻读学位\",\"DSNAME_606453\":\"导师\",\"PYLB_253720\": \"培养类别\",\"SELECT_172548\": \"宿舍楼\",\"TEXT_91454\": \"宿舍号\",\"TEXT_24613\": \"手机号\",\"TEXT_826040\": \"紧急联系人电话\",\"RADIO_799044\": \"您的体温情况？\",\"RADIO_384811\": \"您今天是否在校？\",\"RADIO_907280\": \"本人健康情况？\",\"RADIO_716001\": \"同住人健康情况？\",\"RADIO_248990\": \"本人及同住人14天内是否有中高风险地区旅居史或接触过中高风险地区人员？\"}";
                                        JSONObject col = JSON.parseObject(json);
                                        JSONArray fills = JSON.parseArray(fillDetail);
                                        JSONObject fill = (JSONObject) fills.get(0);
                                        SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd");
                                        Date date = new Date(System.currentTimeMillis());

                                        Iterator iter = col.entrySet().iterator();
                                        List<NameValuePair> post = new ArrayList<>();
                                        post.add(new BasicNameValuePair("DATETIME_CYCLE", formatter.format(date)));
                                        while (iter.hasNext()) {
                                            Map.Entry entry = (Map.Entry) iter.next();
                                            post.add(new BasicNameValuePair(entry.getKey().toString(), fill.getString(entry.getKey().toString())));
                                        }
                                        System.out.println(post);
                                        httpPost = new HttpPost("http://dailyreport.hhu.edu.cn/pdc/formDesignApi/dataFormSave?wid="+wid+"&userId="+uid);
                                        httpPost.setEntity(new UrlEncodedFormEntity(post, StandardCharsets.UTF_8));
                                        res = httpClient.execute(httpPost,context);
                                        if(EntityUtils.toString(res.getEntity()).equals("{\"result\":true}")){
                                            log.info("打卡成功");
                                            iter = col.entrySet().iterator();
                                            while (iter.hasNext()) {
                                                Map.Entry entry = (Map.Entry) iter.next();
                                                log.info(entry.getValue()+":"+fill.getString(entry.getKey().toString()));
                                            }
                                            return Code.OK;
                                        }
                                        else{
                                            log.error("打卡失败");
                                            return Code.CHANGE_EHHU;
                                        }
                                    }
                                    else{
                                        res.close();
                                        log.error("dailyreport.hhu.edu.cn识别失败，身份：未知");
                                        return Code.CHANGE_EHHU;
                                    }
                                }
                                else{
                                    res.close();
                                    log.error("打卡页面解析失败！");
                                    return Code.CHANGE_EHHU;
                                }
                            }
                            else{
                                String page = EntityUtils.toString(res.getEntity());
                                res.close();
                                document = Jsoup.parse(page);
                                String msg = document.getElementById("msg").text();
                                if(msg.isEmpty()){
                                    log.error("新版门户登陆失败！");
                                }
                                else{
                                    log.error("新版门户登陆失败！远程服务器提示:"+msg);
                                }
                                return Code.EXIT;
                            }
                        }
                    }
                } catch (ParseException e) {
                    log.error(e.toString());
                    return Code.CHANGE_EHHU;
                }
            } catch (IOException e) {
                log.error(e.toString());
                return Code.CHANGE_EHHU;
            }
        }
    }
}
enum Code {
    EXIT(0),
    CHANGE_EHHU(1),
    OK(2),
    RETRY(3),
    ;

    public int value;

    Code(int value) {
        this.value = value;
    }

}