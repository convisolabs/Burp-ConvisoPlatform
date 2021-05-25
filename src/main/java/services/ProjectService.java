package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import models.project.Project;
import models.services_manager.ServicesManager;

import java.util.*;

public class ProjectService extends FathersService{

    private Set<Project> allocatedProjects = new HashSet<>();
    final String FLOW_ALLOCATED_PROJECTS = "FLOW.ALLOCATED.PROJECTS";

    public ProjectService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    public Project[] getAllocatedProjectsFromApi(){
        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            util.sendStdout("[Re]Loaded projects from API.");
            return graphQLService.getAllocatedAnalysis();
        }catch (Exception e){
            util.sendStderr("Error loading projects.");
            return new Project[0];
        }
    }

    public Project[] getAllocatedProjectsFromLocal(){
        return new Gson().fromJson(callbacks.loadExtensionSetting(FLOW_ALLOCATED_PROJECTS), Project[].class);
    }


    public boolean didAllocatedProjectsChange(){
        Set<Project> allocatedProjectsSavedLocally = new HashSet<>(Arrays.asList(this.getAllocatedProjectsFromLocal()));
        Set<Project> allocatedProjects = new HashSet<>(Arrays.asList(this.getAllocatedProjectsFromApi()));

        if(!allocatedProjectsSavedLocally.equals(allocatedProjects)){
            callbacks.saveExtensionSetting(FLOW_ALLOCATED_PROJECTS, new Gson().toJson(allocatedProjects));
            util.sendStdout("Saved new allocated projects.");
            this.allocatedProjects = allocatedProjects;
            return true;
        }else{
            this.allocatedProjects = allocatedProjectsSavedLocally;
            return false;
        }
    }

    public void verifyAllocatedProjects(){
        Set<Project> allocatedProjects = new HashSet<>(Arrays.asList(this.getAllocatedProjectsFromApi()));
        if(!this.allocatedProjects.containsAll(allocatedProjects)) {
            callbacks.saveExtensionSetting(FLOW_ALLOCATED_PROJECTS, new Gson().toJson(allocatedProjects));
            util.sendStdout("Saved new allocated projects.");
            this.allocatedProjects = allocatedProjects;
        }
    }

    public Set<Integer> getScopeIdsOfProjects(){
        Set<Integer> scopeIds = new HashSet<>();
        for (Project p :
                allocatedProjects) {
            scopeIds.add(p.getScope_id());
        }
        return scopeIds;
    }

//    public Set<Project> getAllocatedProjects() {
//        if (this.alreadyLoaded && (this.lastRequestTime == null || (System.currentTimeMillis() - this.lastRequestTime.getTimeInMillis()) > 1000)) {
//            this.projectService.verifyAllocatedProjects();
//            this.allTemplates = new HashSet<>();
//            this.getAllTemplatesByScopeIds();
//        } else {
//            loadLocalTemplates();
//            if (!this.alreadyLoaded) { // tried to load from local, but nothing was found.
//                this.getAllTemplatesByScopeIds();
//                this.alreadyLoaded = true;
//            }
//        }
//        this.removeDeletedTemplates();
//        return this.allTemplates;
//    }
}
