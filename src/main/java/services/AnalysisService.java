package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import models.graphql.GraphQLResponse;
import models.analysis.Analysis;
import models.analysis.graphql.requests.AllocatedAnalysisQL;
import models.graphql.query.GraphQLQueries;
import models.services_manager.ServicesManager;
import org.apache.http.auth.AuthenticationException;

import java.util.*;

public class AnalysisService extends Service {

    private Set<Analysis> allocatedAnalyses = new HashSet<>();
    private Analysis workingAnalysis;
    final String FLOW_ALLOCATED_PROJECTS = "FLOW.ALLOCATED.PROJECTS";
    final String FLOW_WORKING_PROJECT = "FLOW.WORKING.PROJECT";

    public AnalysisService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    private synchronized void getAllocatedProjectsFromApi() {
        String query = GraphQLQueries.getAllocatedAnalysesQuery;
        String content = null;
        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            content = graphQLService.executeQuery(query);
            GraphQLResponse graphQLResponse = new GraphQLResponse(content);
            AllocatedAnalysisQL allocatedProjectsQL = new Gson().fromJson(graphQLResponse.getContentOfData("allocatedAnalyses"), AllocatedAnalysisQL.class);
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
        for (Analysis p :
                allocatedAnalyses) {
            scopeIds.add(p.getCompanyId());
        }
        return scopeIds;
    }

    public Set<Analysis> getAllocatedProjects() {
        if (this.alreadyLoaded && (this.lastRequestTime == null || (System.currentTimeMillis() - this.lastRequestTime.getTimeInMillis()) > 1000)) {
            this.getAllocatedProjectsFromApi();
        } else if (!alreadyLoaded) {
            loadLocalProjects();
        }
        return this.allocatedAnalyses;
    }

    public Analysis getWorkingAnalysis() {
        return this.workingAnalysis;
    }

    private void checkIfStillWorkingOnProject(){
        if(this.workingAnalysis != null){
            loadLocalProjects();
            this.getAllocatedProjectsFromApi();

            boolean stillWorkingOnProject = false;
            for (Analysis analysis :
                    allocatedAnalyses) {
                if (this.workingAnalysis.getId() == analysis.getId()) {
                    stillWorkingOnProject = true;
                    this.workingAnalysis = analysis;
                    this.saveLocalWorkingProject();
                    break;
                }
            }


            if(!stillWorkingOnProject){
                this.util.sendStdout("Checking status of working project: Working project not in execution anymore.");
                this.workingAnalysis = null;
                this.saveLocalWorkingProject();
            }else{
                this.util.sendStdout("Checking status of working project: Working project still in execution.");
            }
        }else{
            this.util.sendStdout("Checking status of working project: Working project is null.");
        }
    }

    public void updateWorkingProject(){
        if(this.workingAnalysis != null) {
            this.getAllocatedProjectsFromApi();
            for (Analysis p :
                    allocatedAnalyses) {
                if (this.workingAnalysis.getId() == p.getId()) {
                    this.workingAnalysis = p;
                    this.saveLocalWorkingProject();
                    break;
                }
            }
        }
    }

    public void setWorkingProject(int projectID) {
        for (Analysis p :
                this.allocatedAnalyses) {
            if (p.getId() == projectID) {
                this.workingAnalysis = p;
                this.saveLocalWorkingProject();
                return;
            }
        }
    }

    private synchronized void loadLocalProjects() {
        util.sendStdout("Loaded allocated projects.");
        this.allocatedAnalyses = new HashSet<>(Arrays.asList(new Gson().fromJson(callbacks.loadExtensionSetting(FLOW_ALLOCATED_PROJECTS), Analysis[].class)));
        this.alreadyLoaded = true;
    }


    private void loadLocalWorkingProject() {
        this.workingAnalysis = new Gson().fromJson(callbacks.loadExtensionSetting(FLOW_WORKING_PROJECT), Analysis.class);
        if(this.workingAnalysis != null){
            util.sendStdout("Loaded working project, ID:"+this.workingAnalysis.getId());
        }
    }

    public void saveLocalWorkingProject() {
        if(this.workingAnalysis != null){
            util.sendStdout("Saved working project, ID:"+this.workingAnalysis.getId()+".");
        }else{
            util.sendStdout("Resetting the working project.");
        }
        callbacks.saveExtensionSetting(FLOW_WORKING_PROJECT, new Gson().toJson(this.workingAnalysis));
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
