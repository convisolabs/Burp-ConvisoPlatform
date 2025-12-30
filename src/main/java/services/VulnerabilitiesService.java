package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import models.graphql.GraphQLResponse;
import models.services_manager.ServicesManager;
import models.vulnerability.Vulnerability;
import models.vulnerability.graphql.mutations.vulnerability.CreateWebVulnerabilityQL;
import models.vulnerability.graphql.mutations.responses.CreatedVulnerabilityQL;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpResponseException;

public class VulnerabilitiesService extends Service {

    public VulnerabilitiesService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    public CreatedVulnerabilityQL postVulnerability(Vulnerability vulnerability) throws AuthenticationException, HttpResponseException, NullPointerException, JsonSyntaxException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        CreateWebVulnerabilityQL newVulnerability = new CreateWebVulnerabilityQL(vulnerability);
        String response = graphQLService.executeQuery(newVulnerability.getQuery());
        try {
            GraphQLResponse graphQLResponse = new GraphQLResponse(response);
            return new Gson().fromJson(graphQLResponse.getContentOfData("createWebVulnerability"), CreatedVulnerabilityQL.class);
        } catch (Error error) {
            util.sendStderr("GraphQL error response: " + response);
            throw error;
        }
    }

    public CreatedVulnerabilityQL postNotification(Vulnerability vulnerability) throws AuthenticationException, HttpResponseException, NullPointerException, JsonSyntaxException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        CreateWebVulnerabilityQL createNotificationIssueQL = new CreateWebVulnerabilityQL(vulnerability);
        String response = graphQLService.executeQuery(createNotificationIssueQL.getQuery());
        try {
            GraphQLResponse graphQLResponse = new GraphQLResponse(response);
            return new Gson().fromJson(graphQLResponse.getContentOfData("createWebVulnerability"), CreatedVulnerabilityQL.class);
        } catch (Error error) {
            util.sendStderr("GraphQL error response: " + response);
            throw error;
        }

    }
}
