package http;

import burp.*;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import jdk.jfr.ContentType;
import models.vulnerability.Vulnerability;
import org.apache.http.*;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import utilities.Util;


import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class HttpClient {

    //https://api.convisoappsec.com/

//    private static final String CONVISO_API_HOST = "app.conviso.com.br";
    private static String CONVISO_API_HOST = "homologa.conviso.com.br";
    private static final String CONVISO_API_PATH = "/graphql";
    private static final String FLOW_API_KEY = "FLOW.API.KEY";
    private static final String FLOW_ENDPOINT_URL = "FLOW.ENDPOINT.URL";
    private static String flowApiKey;
    private static final String userAgent = "AppSecFlow-BurpExtender/1.4-develop";

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final Util util;

    public HttpClient(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(callbacks, helpers);
        flowApiKey = callbacks.loadExtensionSetting(FLOW_API_KEY);
        CONVISO_API_HOST = (callbacks.loadExtensionSetting(FLOW_ENDPOINT_URL) == null || callbacks.loadExtensionSetting(FLOW_ENDPOINT_URL).equals("")) ? "app.conviso.com.br" : callbacks.loadExtensionSetting(FLOW_ENDPOINT_URL);
    }

    public String get(String sufixPath) {
        List<String> headers = new ArrayList<>();
        headers.add("GET " + CONVISO_API_PATH + sufixPath +"/ HTTP/1.1");
        headers.add("Host: " + CONVISO_API_HOST);
        headers.add("User-Agent: "+userAgent);
        headers.add("Content-type: application/json");


        if ( flowApiKey != null) {
            headers.add("x-api-key: "+flowApiKey);
        }else{
            this.util.sendStderr("API Key NOT defined!");
        }
        headers.add("Connection: close");

        byte[] request = this.helpers.buildHttpMessage(headers, null);
        byte[] response = this.callbacks.makeHttpRequest(CONVISO_API_HOST, 443, true, request);

        return helpers.bytesToString(response);

    }

    public String get(String sufixPath, Map<String, String> params) {
        List<String> headers = new ArrayList<>();
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(CONVISO_API_PATH);
        stringBuilder.append(sufixPath);
        stringBuilder.append("/");

        if(params.size() > 0){
            stringBuilder.append("?");
            for(Map.Entry<String, String> p: params.entrySet()){
                stringBuilder.append(p.getKey());
                stringBuilder.append("=");
                stringBuilder.append(p.getValue());
            }
        }

        headers.add("GET " + stringBuilder.toString() +" HTTP/1.1");
        headers.add("Host: " + CONVISO_API_HOST);
        headers.add("User-Agent: "+userAgent);
        headers.add("Content-type: application/json");


        if ( flowApiKey != null) {
            headers.add("x-api-key: "+flowApiKey);
        }else{
            this.util.sendStderr("API Key NOT defined!");
        }
        headers.add("Connection: close");

        byte[] request = this.helpers.buildHttpMessage(headers, null);
        byte[] response = this.callbacks.makeHttpRequest(CONVISO_API_HOST, 443, true, request);

        return helpers.bytesToString(response);

    }

    public String post(String jsonBody) {
        List<String> headers = new ArrayList<>();
        headers.add("POST " + CONVISO_API_PATH  +"/ HTTP/1.1");
        headers.add("Host: " + CONVISO_API_HOST);
        headers.add("User-Agent: "+userAgent);
        headers.add("Content-type: application/json");

        if ( flowApiKey != null) {
            headers.add("x-api-key: "+flowApiKey);
        }else{
            this.util.sendStderr("API Key NOT defined!");
        }

        byte[] request = this.helpers.buildHttpMessage(headers, jsonBody.getBytes());
        byte[] response = this.callbacks.makeHttpRequest(CONVISO_API_HOST, 443, true, request);

        return this.helpers.bytesToString(response);

    }


    public HttpResponse postMultiForm(HttpEntity httpMultipartEntity){
        try {

            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost("https://"+CONVISO_API_HOST+CONVISO_API_PATH);

            HttpHost proxy = new HttpHost("127.0.0.1", 8080, "http");
            RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
            httpPost.setConfig(config);


            httpPost.setHeader("User-Agent", userAgent);
            httpPost.setHeader("x-api-key", flowApiKey);
            httpPost.setEntity(httpMultipartEntity);
            HttpResponse response = httpClient.execute(httpPost);
            return response;
        } catch (IOException e) {
            util.sendStderr("Connection not established");
            return null;
        }

    }





}
