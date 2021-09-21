package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import models.graphql.GraphQLResponse;
import models.issue.template.Template;
import models.services_manager.ServicesManager;
import models.issue.Issue;
import models.issue.graphql.mutations.notification.CreateNotificationIssueQL;
import models.issue.graphql.mutations.vulnerability.CreateWebVulnerabilityQL;
import models.issue.graphql.mutations.responses.CreatedIssueQL;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpResponseException;
import view.issues_tab.NewIssueTab;

import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class IssuesService extends Service {

    private static final String FLOW_SAVED_ISSUES = "FLOW.SAVED.ISSUES";
    private Set<String> savedIssues = new HashSet<>();

    public IssuesService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    public CreatedIssueQL postVulnerability(Issue issue) throws FileNotFoundException, AuthenticationException, HttpResponseException, NullPointerException, JsonSyntaxException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        CreateWebVulnerabilityQL newVulnerability = new CreateWebVulnerabilityQL(issue);
        String response = graphQLService.executeQueryMultipart(newVulnerability.getHttpEntity());
        GraphQLResponse graphQLResponse = new GraphQLResponse(response);
        return new Gson().fromJson(graphQLResponse.getContentOfData("createWebVulnerability"), CreatedIssueQL.class);
    }

    public CreatedIssueQL postNotification(Issue issue) throws FileNotFoundException, AuthenticationException, HttpResponseException, NullPointerException, JsonSyntaxException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        CreateNotificationIssueQL createNotificationIssueQL = new CreateNotificationIssueQL(issue);
        String response = graphQLService.executeQueryMultipart(createNotificationIssueQL.getHttpEntity());
        GraphQLResponse graphQLResponse = new GraphQLResponse(response);
        return new Gson().fromJson(graphQLResponse.getContentOfData("createNotification"), CreatedIssueQL.class);

    }

    public synchronized void clearWorkingIssues(){
        this.savedIssues = new HashSet<>();
        this.saveWorkingIssuesLocally();
    }

    public synchronized void addToWorkingIssues(String issueAsString){
        savedIssues.add(issueAsString);
    }

    public synchronized void removeFromWorkingIssues(String issueAsString){
        savedIssues.remove(issueAsString);
    }

    public boolean verifySavedIssue(String issueAsString){
        return savedIssues.contains(issueAsString);
    }

    public synchronized void saveWorkingIssuesLocally(){
        String toSave = new Gson().toJson(this.savedIssues);
        if (!toSave.equals(callbacks.loadExtensionSetting(FLOW_SAVED_ISSUES))) {
            callbacks.saveExtensionSetting(FLOW_SAVED_ISSUES, toSave);
            util.sendStdout("Saved working issues locally.");
        } else {
            util.sendStdout("Saved working issues are the same.");
        }
    }

    public synchronized void loadWorkingIssuesLocally(){
        String savedIssues = callbacks.loadExtensionSetting(FLOW_SAVED_ISSUES);
        if (savedIssues != null && !savedIssues.equals(new Gson().toJson(this.savedIssues))) {
            this.savedIssues = new HashSet<>(Arrays.asList(new Gson().fromJson(savedIssues, String[].class)));
            util.sendStdout("Loaded working issues from local.");
            this.alreadyLoaded = true;
        } else {
            if(this.savedIssues.size() > 0){
                util.sendStdout("Working issues are equal to memory issues.");
            }else{
                util.sendStdout("Didn't find working issues saved locally.");
            }

        }
    }

    public Set<String> getSavedIssues() {
        return savedIssues;
    }
}
