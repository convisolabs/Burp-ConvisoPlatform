package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import com.google.gson.Gson;
import http.HttpClient;
import models.project.Project;
import utilities.Util;

import java.util.*;

public class ProjectService {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private Set<Project> allocatedProjects = new HashSet<>();
    private final Util util;
    final String FLOW_ALLOCATED_PROJECTS = "FLOW.ALLOCATED.PROJECTS";

    public ProjectService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
    }

    public Project[] getAllocatedProjectsFromApi(){
        Project[] projectsArray;
        HttpClient httpClient = new HttpClient(callbacks, helpers);
        String httpResult = httpClient.get("/v2/running_analyses_by_api_key");
        IResponseInfo responseCleaned = helpers.analyzeResponse(helpers.stringToBytes(httpResult));
        String jsonResponse = httpResult.substring(responseCleaned.getBodyOffset());
        try{
            projectsArray = new Gson().fromJson(jsonResponse, Project[].class);
            util.sendStdout("[Re]Loaded projects from API.");
            return projectsArray;
        }catch (com.google.gson.JsonSyntaxException e) {
            util.sendStderr(jsonResponse);
            return new Project[0];
        }catch (Exception e){
            util.sendStderr("Error loading templates.");
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
        scopeIds.add(11);
        for (Project p :
                allocatedProjects) {
            scopeIds.add(p.getScope_id());
        }
        return scopeIds;
    }

}
