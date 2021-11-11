package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import com.google.gson.Gson;
import http.HttpClient;
import models.graphql.GraphQLQuery;
import models.graphql.query.GraphQLQueries;
import models.services_manager.ServicesManager;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class GraphQLService extends Service {

    public GraphQLService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    public Boolean testApiKey() {
        try {
            this.executeQuery(GraphQLQueries.testAPIKey);
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

    public String executeQueryMultipart(HttpEntity httpEntity) throws AuthenticationException, HttpResponseException, NullPointerException {
        HttpClient httpClient = new HttpClient(this.callbacks, this.helpers);
        HttpResponse response = httpClient.postMultiForm(httpEntity);
        String responseContent = null;
        try {
            responseContent = EntityUtils.toString(response.getEntity());
        } catch (IOException exception) {
            throw new HttpResponseException(response.getStatusLine().getStatusCode(), "Something is wrong with the content!");
        } catch(NullPointerException nullPointerException){
            throw new NullPointerException();
        }

        try {
            EntityUtils.consume(response.getEntity());
        } catch (IOException ignored) {
            System.gc();
        }

        if (responseContent != null) {
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == 200) {
                return responseContent;
            } else if (statusCode == 401) {
                throw new AuthenticationException();
            } else {
                throw new HttpResponseException(response.getStatusLine().getStatusCode(), "");
            }
        } else {
            throw new NullPointerException();
        }

    }

}
