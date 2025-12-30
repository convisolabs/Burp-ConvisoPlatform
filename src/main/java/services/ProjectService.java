package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import models.graphql.GraphQLQuery;
import models.graphql.GraphQLResponse;
import models.project.Project;
import models.project.graphql.requests.AllocatedProjectQL;
import models.graphql.query.GraphQLQueries;
import models.services_manager.ServicesManager;
import org.apache.http.auth.AuthenticationException;
import models.activity.Activity;

import java.util.*;

public class ProjectService extends Service {

    private Set<Project> allocatedProjects = new HashSet<>();
    private Project workingProject;
    final String CONVISO_ALLOCATED_PROJECTS = "CONVISO.ALLOCATED.PROJECTS";
    final String CONVISO_WORKING_PROJECT = "CONVISO.WORKING.PROJECT";

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
            AllocatedProjectQL allocatedProjectsQL = new Gson().fromJson(graphQLResponse.getContentOfData("allocatedProjects"), AllocatedProjectQL.class);
            allocatedProjectsQL.sanitizeProjects();
            this.allocatedProjects = new HashSet<>(Arrays.asList(allocatedProjectsQL.getCollection()));
            this.saveLocalProjects();
            this.setLastRequest();
            util.sendStdout("[Re]Loaded projects from API.");
        } catch (AuthenticationException e) {
            util.sendStderr("Invalid API KEY.");
            this.allocatedProjects = new HashSet<>();
        } catch (Exception e) {
            util.sendStderr("Error [re]loading projects.");
            util.sendStderr(content);
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
        return this.allocatedProjects;
    }

    public Set<Project> getProjectsByCompanyId(int companyId) throws AuthenticationException {
        String content = null;
        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            HashMap<String, Object> params = new HashMap<>();
            params.put("scopeIdEq", companyId);
            params.put("showHidden", true);

            HashMap<String, Object> variables = new HashMap<>();
            variables.put("page", 1);
            variables.put("limit", 1000);
            variables.put("params", params);
            variables.put("sortBy", "label");
            variables.put("descending", false);

            GraphQLQuery graphQLQuery = new GraphQLQuery(GraphQLQueries.getProjectsByCompanyQuery, variables, "projects");
            content = graphQLService.executeQuery(graphQLQuery);
            GraphQLResponse graphQLResponse = new GraphQLResponse(content);
            AllocatedProjectQL projectsQL = new Gson().fromJson(graphQLResponse.getContentOfData("projects"), AllocatedProjectQL.class);
            projectsQL.sanitizeProjects();
            Set<Project> projects = new HashSet<>(Arrays.asList(projectsQL.getCollection()));
            util.sendStdout("Loaded projects by company ID: " + companyId + ". Count: " + projects.size());
            return projects;
        } catch (AuthenticationException e) {
            throw e;
        } catch (Error e) {
            util.sendStderr("GraphQL error loading projects by company.");
            util.sendStderr(e.toString());
            util.sendStderr(content);
            return new HashSet<>();
        } catch (Exception e) {
            util.sendStderr("Error loading projects by company.");
            util.sendStderr(content);
            return new HashSet<>();
        }
    }

    public Project getProjectById(int projectId) throws AuthenticationException {
        String content = null;
        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            String query = String.format(GraphQLQueries.getProjectById, projectId);
            util.sendStdout("Loading project requirements for project ID: " + projectId);
            content = graphQLService.executeQuery(query);
            GraphQLResponse graphQLResponse = new GraphQLResponse(content);
            Project project = new Gson().fromJson(graphQLResponse.getContentOfData("project"), Project.class);
            if (project == null) {
                util.sendStderr("Project query returned null for project ID: " + projectId);
                util.sendStderr(content);
                return null;
            }
            project.sanitize();
            if (project.getActivities() == null) {
                util.sendStderr("Project query returned no activities for project ID: " + projectId);
                util.sendStderr(content);
                project.setActivities(new Activity[0]);
            }
            this.workingProject = project;
            return project;
        } catch (AuthenticationException e) {
            throw e;
        } catch (Error e) {
            util.sendStderr("GraphQL error loading project by id.");
            util.sendStderr(e.toString());
            util.sendStderr(content);
            return null;
        } catch (Exception e) {
            util.sendStderr("Error loading project by id.");
            util.sendStderr(content);
            return null;
        }
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
                    allocatedProjects) {
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
                    allocatedProjects) {
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
        try {
            this.allocatedProjects = new HashSet<>(Arrays.asList(new Gson().fromJson(callbacks.loadExtensionSetting(CONVISO_ALLOCATED_PROJECTS), Project[].class)));
        }catch (NullPointerException exception){
            util.sendStderr("No projects saved locally.");
            this.getAllocatedProjectsFromApi();
        }
        this.alreadyLoaded = true;
    }


    private void loadLocalWorkingProject() {
        this.workingProject = new Gson().fromJson(callbacks.loadExtensionSetting(CONVISO_WORKING_PROJECT), Project.class);
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
        callbacks.saveExtensionSetting(CONVISO_WORKING_PROJECT, new Gson().toJson(this.workingProject));
    }

    private void saveLocalProjects() {
        callbacks.saveExtensionSetting(CONVISO_ALLOCATED_PROJECTS, new Gson().toJson(this.allocatedProjects));
        util.sendStdout("Saved new allocated projects.");
    }

    public void getReadyForView(){
        this.loadLocalWorkingProject();
        new Thread(this::checkIfStillWorkingOnProject).start();
    }
}
