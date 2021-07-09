package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import models.graphql.GraphQLResponse;
import models.services_manager.ServicesManager;
import models.vulnerability.Issue;
import models.vulnerability.graphql.mutations.notification.CreateNotificationIssueQL;
import models.vulnerability.graphql.mutations.vulnerability.CreateWebVulnerabilityQL;
import models.vulnerability.graphql.responses.CreatedIssueQL;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpResponseException;

import java.io.FileNotFoundException;

public class IssuesService extends Service {

    public IssuesService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    public CreatedIssueQL postVulnerability(Issue issue) throws FileNotFoundException, AuthenticationException, HttpResponseException, NullPointerException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        CreateWebVulnerabilityQL newVulnerability = new CreateWebVulnerabilityQL(issue);
        String response = graphQLService.executeQueryMultipart(newVulnerability.getHttpEntity());
        GraphQLResponse graphQLResponse = new GraphQLResponse(response);
        return new Gson().fromJson(graphQLResponse.getContentOfData("createWebVulnerability"), CreatedIssueQL.class);
    }

    public CreatedIssueQL postNotification(Issue issue) throws FileNotFoundException, AuthenticationException, HttpResponseException, NullPointerException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        CreateNotificationIssueQL createNotificationIssueQL = new CreateNotificationIssueQL(issue);
        String response = graphQLService.executeQueryMultipart(createNotificationIssueQL.getHttpEntity());
        GraphQLResponse graphQLResponse = new GraphQLResponse(response);
        return new Gson().fromJson(graphQLResponse.getContentOfData("createNotification"), CreatedIssueQL.class);

    }
}
