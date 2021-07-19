package models.services_manager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import services.*;

public class ServicesManager {


    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private GraphQLService graphQLService;
    private AnalysisService analysisService;
    private TemplateService templateService;
    private IssuesService issuesService;
    private ActivityService activityService;

    public ServicesManager(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.graphQLService = new GraphQLService(this.callbacks, this.helpers, this);
        this.analysisService = new AnalysisService(this.callbacks, this.helpers, this);
        this.templateService = new TemplateService(this.callbacks, this.helpers, this);
        this.issuesService = new IssuesService(this.callbacks, this.helpers, this);
        this.activityService = new ActivityService(this.callbacks, this.helpers, this);
    }

    public GraphQLService getGraphQLService() {
        return graphQLService;
    }

    public AnalysisService getAnalysisService() {
        return analysisService;
    }

    public TemplateService getTemplateService() {
        return templateService;
    }

    public IssuesService getVulnerabilityService() {
        return issuesService;
    }

    public ActivityService getActivityService() {
        return activityService;
    }
}
