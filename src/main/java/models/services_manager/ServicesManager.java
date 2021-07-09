package models.services_manager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import services.GraphQLService;
import services.AnalysisService;
import services.TemplateService;
import services.IssuesService;

public class ServicesManager {

    private GraphQLService graphQLService;
    private AnalysisService analysisService;
    private TemplateService templateService;
    private IssuesService issuesService;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    public ServicesManager(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.graphQLService = new GraphQLService(this.callbacks, this.helpers, this);
        this.analysisService = new AnalysisService(this.callbacks, this.helpers, this);
        this.templateService = new TemplateService(this.callbacks, this.helpers, this);
        this.issuesService = new IssuesService(this.callbacks, this.helpers, this);
    }

    public GraphQLService getGraphQLService() {
        return graphQLService;
    }

    public AnalysisService getProjectService() {
        return analysisService;
    }

    public TemplateService getTemplateService() {
        return templateService;
    }

    public IssuesService getVulnerabilityService() {
        return issuesService;
    }


}
