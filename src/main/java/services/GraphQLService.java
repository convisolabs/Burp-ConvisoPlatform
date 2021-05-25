package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import http.HttpClient;
import models.graphql.GraphQL;
import models.project.AllocatedProjectsQL;
import models.project.Project;
import models.services_manager.ServicesManager;

import java.nio.charset.StandardCharsets;

public class GraphQLService extends FathersService{
    private int limit = 1000;

    public GraphQLService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }


    public Project[] getAllocatedAnalysis() {
        int actualPage = 1;
        String query = "query{ allocatedProjects(page: " + actualPage + ", limit: " + limit + "){ collection{id label endDate } metadata{ currentPage limitValue totalCount totalPages } } }";
        String content = this.executeQuery(query);
        try{
            Gson gson = new Gson();
            AllocatedProjectsQL allocatedProjectsQL =
                    gson.fromJson(((JsonObject) (gson.fromJson(content, JsonObject.class)).get("data")).get("allocatedProjects"), AllocatedProjectsQL.class);
            allocatedProjectsQL.sanitizeProjects();

            return allocatedProjectsQL.getCollection();
        }catch (NullPointerException e){
            util.sendStderr(content);
            throw new NullPointerException();
        }
    }


    private String executeQuery(String query){
        GraphQL graphQL = new GraphQL(query);
        HttpClient httpClient = new HttpClient(this.callbacks, this.helpers);
        String response = httpClient.post(new Gson().toJson(graphQL));
        IResponseInfo responseInfo = this.helpers.analyzeResponse(response.getBytes(StandardCharsets.UTF_8));
        int bodyOffset = responseInfo.getBodyOffset();
        return response.substring(bodyOffset);
    }

}
