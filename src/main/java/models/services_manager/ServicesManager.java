package models.services_manager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import services.GraphQLService;
import services.ProjectService;
import services.TemplateService;
import services.VulnerabilityService;

public class ServicesManager {

    private GraphQLService graphQLService;
    private ProjectService projectService;
    private TemplateService templateService;
    private VulnerabilityService vulnerabilityService;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    public ServicesManager(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.graphQLService = new GraphQLService(this.callbacks, this.helpers, this);
        this.projectService = new ProjectService(this.callbacks, this.helpers, this);
        this.templateService = new TemplateService(this.callbacks, this.helpers, this);
        this.vulnerabilityService = new VulnerabilityService(this.callbacks, this.helpers, this);
    }

    public GraphQLService getGraphQLService() {
        return graphQLService;
    }

    public void setGraphQLService(GraphQLService graphQLService) {
        this.graphQLService = graphQLService;
    }

    public ProjectService getProjectService() {
        return projectService;
    }

    public void setProjectService(ProjectService projectService) {
        this.projectService = projectService;
    }

    public TemplateService getTemplateService() {
        return templateService;
    }

    public void setTemplateService(TemplateService templateService) {
        this.templateService = templateService;
    }

    public VulnerabilityService getVulnerabilityService() {
        return vulnerabilityService;
    }

    public void setVulnerabilityService(VulnerabilityService vulnerabilityService) {
        this.vulnerabilityService = vulnerabilityService;
    }
}
