package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import models.activity.graphql.mutations.UpdateActivityStatusToFinish;
import models.activity.graphql.mutations.UpdateActivityStatusToNotApply;
import models.activity.graphql.mutations.UpdateActivityStatusToRestart;
import models.activity.graphql.mutations.UpdateActivityStatusToStart;
import models.activity.graphql.mutations.responses.UpdatedActivityToFinish;
import models.activity.graphql.mutations.responses.UpdatedActivityToNotApply;
import models.activity.graphql.mutations.responses.UpdatedActivityToRestart;
import models.activity.graphql.mutations.responses.UpdatedActivityToStart;
import models.attachments.AttachmentArchive;
import models.graphql.GraphQLResponse;
import models.services_manager.ServicesManager;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpResponseException;

import java.io.FileNotFoundException;

public class ActivityService extends Service {
    private final ProjectService projectService;

    public ActivityService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
        this.projectService = servicesManager.getProjectService();
    }

    public void updateActivityToFinish(int activityId, AttachmentArchive attachmentArchive, String evidenceText) throws AuthenticationException, FileNotFoundException, HttpResponseException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        UpdatedActivityToFinish updatedActivityToFinish = null;

        if (attachmentArchive != null && !evidenceText.isEmpty()){
            String response = graphQLService.executeQueryMultipart(new UpdateActivityStatusToFinish(activityId, attachmentArchive, evidenceText).getHttpEntity());
            GraphQLResponse graphQLResponse = new GraphQLResponse(response);
            updatedActivityToFinish = new Gson().fromJson(graphQLResponse.getContentOfData("updateActivityStatus"), UpdatedActivityToFinish.class);

        } else if (attachmentArchive != null) {
            String response = graphQLService.executeQueryMultipart(new UpdateActivityStatusToFinish(activityId, attachmentArchive).getHttpEntity());
            GraphQLResponse graphQLResponse = new GraphQLResponse(response);
            updatedActivityToFinish = new Gson().fromJson(graphQLResponse.getContentOfData("updateActivityStatus"), UpdatedActivityToFinish.class);
        } else {
            String response = graphQLService.executeQuery(new UpdateActivityStatusToFinish(activityId, evidenceText).getQuery());
            GraphQLResponse graphQLResponse = new GraphQLResponse(response);
            updatedActivityToFinish = new Gson().fromJson(graphQLResponse.getContentOfData("updateActivityStatus"), UpdatedActivityToFinish.class);
        }

        if (updatedActivityToFinish != null) {
            projectService.getWorkingProject().updateActivity(updatedActivityToFinish.getActivity());
            projectService.saveLocalWorkingProject();
        }
    }


    public void updateActivityToNotApply(int activityId, String justification) throws AuthenticationException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        UpdatedActivityToNotApply updatedActivityToNotApply;

        String response = graphQLService.executeQuery(new UpdateActivityStatusToNotApply(activityId, justification).getQuery());
        GraphQLResponse graphQLResponse = new GraphQLResponse(response);
        updatedActivityToNotApply = new Gson().fromJson(graphQLResponse.getContentOfData("updateActivityStatus"), UpdatedActivityToNotApply.class);

        if(updatedActivityToNotApply != null){
            projectService.getWorkingProject().updateActivity(updatedActivityToNotApply.getActivity());
            projectService.saveLocalWorkingProject();
        }
    }

    public void updateActivityToStart(int activityId) throws AuthenticationException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        UpdatedActivityToStart updatedActivityToStart;

        String response = graphQLService.executeQuery(new UpdateActivityStatusToStart(activityId).getQuery());
        GraphQLResponse graphQLResponse = new GraphQLResponse(response);
        updatedActivityToStart = new Gson().fromJson(graphQLResponse.getContentOfData("updateActivityStatus"), UpdatedActivityToStart.class);

        if(updatedActivityToStart != null){
            projectService.getWorkingProject().updateActivity(updatedActivityToStart.getActivity());
            projectService.saveLocalWorkingProject();
        }
    }

    public void updateActivityToRestart(int activityId) throws AuthenticationException {
        GraphQLService graphQLService = this.servicesManager.getGraphQLService();
        UpdatedActivityToRestart updatedActivityToRestart;

        String response = graphQLService.executeQuery(new UpdateActivityStatusToRestart(activityId).getQuery());
        GraphQLResponse graphQLResponse = new GraphQLResponse(response);
        updatedActivityToRestart = new Gson().fromJson(graphQLResponse.getContentOfData("updateActivityStatus"), UpdatedActivityToRestart.class);

        if(updatedActivityToRestart != null){
            projectService.getWorkingProject().updateActivity(updatedActivityToRestart.getActivity());
            projectService.saveLocalWorkingProject();
        }
    }


}
