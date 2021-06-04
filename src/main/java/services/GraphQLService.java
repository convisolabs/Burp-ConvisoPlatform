package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import com.google.gson.Gson;
import http.HttpClient;
import models.graphql.GraphQLQuery;
import models.services_manager.ServicesManager;
import org.apache.http.HttpEntity;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpResponseException;

import javax.swing.*;
import java.nio.charset.StandardCharsets;

public class GraphQLService extends Service {

    public GraphQLService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    public Boolean testApiKey() {
        String query = "query{ allocatedProjects(page: " + 1 + ", limit: " + 1 + "){ collection{} } }";

        try {
            this.executeQuery(query);
            this.util.sendStdout("API Key OK!");
            return true;
        } catch (AuthenticationException e) {
            this.util.sendStderr("API Key NOT OK!");
            this.util.sendStderr("Status code: " + 401);
            this.util.sendStderr(e.getMessage());
            return false;
        }
    }


    public String executeQuery(String query) throws AuthenticationException {
        GraphQLQuery graphQL = new GraphQLQuery(query);
        HttpClient httpClient = new HttpClient(this.callbacks, this.helpers);
        String response = httpClient.post(new Gson().toJson(graphQL));
        IResponseInfo responseInfo = this.helpers.analyzeResponse(response.getBytes(StandardCharsets.UTF_8));
        int bodyOffset = responseInfo.getBodyOffset();
        if (responseInfo.getStatusCode() == 401) {
            throw new AuthenticationException(response.substring(bodyOffset));
        }
        return response.substring(bodyOffset);
    }

    public String executeQueryMultipart(HttpEntity httpEntity) throws AuthenticationException, HttpResponseException {
        HttpClient httpClient = new HttpClient(this.callbacks, this.helpers);
        IResponseInfo response = httpClient.postMultiForm(httpEntity);
        if (response != null) {
            int statusCode = response.getStatusCode();
            if (statusCode == 201) {
                return "";
            } else if (statusCode == 401) {
                throw new AuthenticationException();
            } else {
                throw new HttpResponseException(response.getStatusCode(), "");
            }
        } else {
            throw new NullPointerException();
        }

    }

}
