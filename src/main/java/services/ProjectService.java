package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import models.graphql.GraphQLResponse;
import models.project.Project;
import models.project.graphql.requests.AllocatedProjectQL;
import models.graphql.query.GraphQLQueries;
import models.services_manager.ServicesManager;
import org.apache.http.auth.AuthenticationException;

import java.util.*;

public class ProjectService extends Service {

    private Set<Project> allocatedAnalyses = new HashSet<>();
    private Project workingProject;
    final String FLOW_ALLOCATED_PROJECTS = "FLOW.ALLOCATED.PROJECTS";
    final String FLOW_WORKING_PROJECT = "FLOW.WORKING.PROJECT";

    public ProjectService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    private synchronized void getAllocatedProjectsFromApi() {
        String query = GraphQLQueries.getAllocatedProjectsQuery;
        String content = null;
        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            content = graphQLService.executeQuery(query);
            GraphQLResponse graphQLResponse = new GraphQLResponse(content);
            AllocatedProjectQL allocatedProjectsQL = new Gson().fromJson(graphQLResponse.getContentOfData("allocatedAnalyses"), AllocatedProjectQL.class);
            allocatedProjectsQL.sanitizeProjects();
            this.allocatedAnalyses = new HashSet<>(Arrays.asList(allocatedProjectsQL.getCollection()));
            this.saveLocalProjects();
            this.setLastRequest();
            util.sendStdout("[Re]Loaded analyses from API.");
        } catch (AuthenticationException e) {
            util.sendStderr("Invalid API KEY.");
            this.allocatedAnalyses = new HashSet<>();
        } catch (Exception e) {
            util.sendStderr("Error [re]loading analyses.");
            util.sendStderr(content);
            this.allocatedAnalyses = new HashSet<>();
        }
    }

    public Set<Integer> getScopeIdsOfProjects() {
        if(this.alreadyLoaded){
            this.getAllocatedProjects();
        }
        Set<Integer> scopeIds = new HashSet<>();
        for (Project p :
                allocatedAnalyses) {
            scopeIds.add(p.getCompanyId());
        }
        return scopeIds;
    }

    public Set<Project> getAllocatedProjects() {
        if (this.alreadyLoaded && (this.lastRequestTime == null || (System.currentTimeMillis() - this.lastRequestTime.getTimeInMillis()) > 1000)) {
            this.getAllocatedProjectsFromApi();
        } else if (!alreadyLoaded) {
            loadLocalProjects();
        }
        return this.allocatedAnalyses;
    }

    public Project getWorkingProject() {
        return this.workingProject;
    }

    private void checkIfStillWorkingOnProject(){
        if(this.workingProject != null){
            loadLocalProjects();
            this.getAllocatedProjectsFromApi();

            boolean stillWorkingOnProject = false;
            for (Project project :
                    allocatedAnalyses) {
                if (this.workingProject.getId() == project.getId()) {
                    stillWorkingOnProject = true;
                    this.workingProject = project;
                    this.saveLocalWorkingProject();
                    break;
                }
            }

            if(!stillWorkingOnProject){
                this.util.sendStdout("Checking status of working project: Working project not in execution anymore.");
                this.workingProject = null;
                this.saveLocalWorkingProject();
            }else{
                this.util.sendStdout("Checking status of working project: Working project still in execution.");
            }
        }else{
            this.util.sendStdout("Checking status of working project: Working project is null.");
        }
    }

    public void updateWorkingProject(){
        if(this.workingProject != null) {
            this.getAllocatedProjectsFromApi();
            for (Project p :
                    allocatedAnalyses) {
                if (this.workingProject.getId() == p.getId()) {
                    this.workingProject = p;
                    this.saveLocalWorkingProject();
                    break;
                }
            }
        }
    }

    public void setWorkingProject(int projectID) {
        for (Project p :
                this.allocatedAnalyses) {
            if (p.getId() == projectID) {
                this.workingProject = p;
                this.saveLocalWorkingProject();
                return;
            }
        }
    }

    private synchronized void loadLocalProjects() {
        util.sendStdout("Loaded allocated projects.");
        try {
            this.allocatedAnalyses = new HashSet<>(Arrays.asList(new Gson().fromJson(callbacks.loadExtensionSetting(FLOW_ALLOCATED_PROJECTS), Project[].class)));
        }catch (NullPointerException exception){
            util.sendStderr("No projects saved locally.");
            this.getAllocatedProjectsFromApi();
        }
        this.alreadyLoaded = true;
    }


    private void loadLocalWorkingProject() {
        this.workingProject = new Gson().fromJson(callbacks.loadExtensionSetting(FLOW_WORKING_PROJECT), Project.class);
        if(this.workingProject != null){
            util.sendStdout("Loaded working project, ID:"+this.workingProject.getId());
        }
    }

    public void saveLocalWorkingProject() {
        if(this.workingProject != null){
            util.sendStdout("Saved working project, ID:"+this.workingProject.getId()+".");
        }else{
            util.sendStdout("Resetting the working project.");
        }
        callbacks.saveExtensionSetting(FLOW_WORKING_PROJECT, new Gson().toJson(this.workingProject));
    }

    private void saveLocalProjects() {
        callbacks.saveExtensionSetting(FLOW_ALLOCATED_PROJECTS, new Gson().toJson(this.allocatedAnalyses));
        util.sendStdout("Saved new allocated projects.");
    }

    public void getReadyForView(){
        this.loadLocalWorkingProject();
        new Thread(this::checkIfStillWorkingOnProject).start();
    }
}
