package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import models.graphql.GraphQLResponse;
import models.project.graphql.AllocatedAnalysisQL;
import models.project.Project;
import models.services_manager.ServicesManager;
import org.apache.http.auth.AuthenticationException;

import java.util.*;

public class ProjectService extends Service {

    private Set<Project> allocatedProjects = new HashSet<>();
    private Project workingProject;
    final String FLOW_ALLOCATED_PROJECTS = "FLOW.ALLOCATED.PROJECTS";
    final String FLOW_WORKING_PROJECT = "FLOW.WORKING.PROJECT";

    public ProjectService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    private synchronized void getAllocatedProjectsFromApi() {
        int actualPage = 1;
        int limit = 1000;
        String query = "query{ allocatedAnalyses(page: " + actualPage + ", limit: " + limit + "){ collection{id label dueDate scopeId} metadata{ currentPage limitValue totalCount totalPages } } }";

        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            String content = graphQLService.executeQuery(query);
            GraphQLResponse graphQLResponse = new GraphQLResponse(content);
            AllocatedAnalysisQL allocatedProjectsQL = new Gson().fromJson(graphQLResponse.getContentOfData("allocatedAnalyses"), AllocatedAnalysisQL.class);
            allocatedProjectsQL.sanitizeProjects();
            this.allocatedProjects = new HashSet<>(Arrays.asList(allocatedProjectsQL.getCollection()));
            this.saveLocalProjects();
            this.setLastRequest();
            util.sendStdout("[Re]Loaded projects from API.");
        } catch (AuthenticationException e) {
            util.sendStderr("Invalid API KEY.");
            this.allocatedProjects = new HashSet<>();
        } catch (Exception e) {
            util.sendStderr("Error loading projects.");
            this.allocatedProjects = new HashSet<>();
        }
    }

    public Set<Integer> getScopeIdsOfProjects() {
        if(this.alreadyLoaded){
            this.getAllocatedProjects();
        }
        Set<Integer> scopeIds = new HashSet<>();
        for (Project p :
                allocatedProjects) {
            scopeIds.add(p.getScopeId());
        }
        return scopeIds;
    }

    public Set<Project> getAllocatedProjects() {
        if (this.alreadyLoaded && (this.lastRequestTime == null || (System.currentTimeMillis() - this.lastRequestTime.getTimeInMillis()) > 1000)) {
            this.getAllocatedProjectsFromApi();
        } else if (!alreadyLoaded) {
            loadLocalProjects();
        }
        return this.allocatedProjects;
    }

    public Project getWorkingProject() {
        return workingProject;
    }

    private void checkIfStillWorkingOnProject(){
        this.util.sendStdout("Checking status of working project:");
        if(this.workingProject != null){
            loadLocalProjects();
            this.getAllocatedProjectsFromApi();

            boolean stillWorkingOnProject = false;
            for (Project p :
                    allocatedProjects) {
                if (this.workingProject.getId() == p.getId()) {
                    stillWorkingOnProject = true;
                    break;
                }
            }

            if(!stillWorkingOnProject){
                this.util.sendStdout("Working project not in execution anymore.");
                this.workingProject = null;
                this.saveLocalWorkingProject();
            }else{
                this.util.sendStdout("Working project still in execution.");
            }
        }else{
            this.util.sendStdout("Working project is null. Exiting!");
        }
    }

    public void setWorkingProject(int projectID) {
        for (Project p :
                this.allocatedProjects) {
            if (p.getId() == projectID) {
                this.workingProject = p;
                this.saveLocalWorkingProject();
                return;
            }
        }
    }

    private synchronized void loadLocalProjects() {
        util.sendStdout("Loaded allocated projects.");
        this.allocatedProjects = new HashSet<>(Arrays.asList(new Gson().fromJson(callbacks.loadExtensionSetting(FLOW_ALLOCATED_PROJECTS), Project[].class)));
        this.alreadyLoaded = true;
    }


    private void loadLocalWorkingProject() {
        this.workingProject = new Gson().fromJson(callbacks.loadExtensionSetting(FLOW_WORKING_PROJECT), Project.class);
        if(this.workingProject != null){
            util.sendStdout("Loaded working project, ID:"+this.workingProject.getId());
        }
    }

    private void saveLocalWorkingProject() {
        if(this.workingProject != null){
            util.sendStdout("Saved working project, ID:"+this.workingProject.getId()+".");
        }else{
            util.sendStdout("Resetting the working project.");
        }
        callbacks.saveExtensionSetting(FLOW_WORKING_PROJECT, new Gson().toJson(this.workingProject));
    }

    private void saveLocalProjects() {
        callbacks.saveExtensionSetting(FLOW_ALLOCATED_PROJECTS, new Gson().toJson(this.allocatedProjects));
        util.sendStdout("Saved new allocated projects.");
    }

    public void getReadyForView(){
        this.loadLocalWorkingProject();
        new Thread(this::checkIfStillWorkingOnProject).start();

    }
}
