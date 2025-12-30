package models.services_manager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import services.*;

public class ServicesManager {


    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private GraphQLService graphQLService;
    private AssetService assetService;
    private ProjectService projectService;
    private TemplateService templateService;
    private VulnerabilitiesService vulnerabilitiesService;
    private ActivityService activityService;

    public ServicesManager(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.graphQLService = new GraphQLService(this.callbacks, this.helpers, this);
        this.assetService = new AssetService(this.callbacks, this.helpers, this);
        this.projectService = new ProjectService(this.callbacks, this.helpers, this);
        this.templateService = new TemplateService(this.callbacks, this.helpers, this);
        this.vulnerabilitiesService = new VulnerabilitiesService(this.callbacks, this.helpers, this);
        this.activityService = new ActivityService(this.callbacks, this.helpers, this);
    }

    public GraphQLService getGraphQLService() {
        return graphQLService;
    }

    public AssetService getAssetService() {
        return assetService;
    }

    public ProjectService getProjectService() {
        return projectService;
    }

    public TemplateService getTemplateService() {
        return templateService;
    }

    public VulnerabilitiesService getVulnerabilityService() {
        return vulnerabilitiesService;
    }

    public ActivityService getActivityService() {
        return activityService;
    }
}
