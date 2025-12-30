package services;

import burp.*;
import models.graphql.GraphQLResponse;
import models.graphql.query.GraphQLQueries;
import models.services_manager.ServicesManager;
import com.google.gson.*;
import models.vulnerability.template.Template;
import models.vulnerability.template.TemplateByCompanyIdQL;
import org.apache.http.auth.AuthenticationException;

import java.util.*;


public class TemplateService extends Service {
    private Set<Template> allTemplates = new HashSet<>();

    private static final String CONVISO_ALL_TEMPLATES = "CONVISO.ALL.TEMPLATES";
    private static final String CONVISO_COMPANY_ID = "CONVISO.COMPANY.ID";

    public TemplateService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
        alreadyLoaded = false;
    }

    public Set<Template> getAllTemplates() {
        if (this.alreadyLoaded && (this.lastRequestTime == null || (System.currentTimeMillis() - this.lastRequestTime.getTimeInMillis()) > 30000)) {
            this.allTemplates = new HashSet<>();
            this.getAllTemplatesByCompanyId();
        } else {
            loadLocalTemplates();
            if (!this.alreadyLoaded) {
                this.getAllTemplatesByCompanyId();
                this.alreadyLoaded = true;
            }
        }
        this.removeDeletedTemplates();
        return this.allTemplates;
    }

    private void getAllVulnerabilitiesModelsFromApi(Integer companyId) {

        String content = null;
        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            content = graphQLService.executeQuery(String.format(GraphQLQueries.getVulnerabilitiesTemplatesByCompany, companyId));
            GraphQLResponse graphQLResponse = new GraphQLResponse(content);
            TemplateByCompanyIdQL templateByCompanyIdQL = new Gson().fromJson(graphQLResponse.getContentOfData("vulnerabilitiesTemplatesByCompanyId"), TemplateByCompanyIdQL.class);
            templateByCompanyIdQL.sanitizeTemplates();
            this.allTemplates.addAll(Arrays.asList(templateByCompanyIdQL.getCollection()));
            this.saveTemplatesLocally();
            util.sendStdout("[Re]Loaded templates from API. Company ID: " + companyId);
        } catch (AuthenticationException e) {
            util.sendStderr("Invalid API KEY.");
        } catch (Exception e) {
            e.printStackTrace();
            util.sendStderr(content);
            util.sendStderr("Error loading projects.");
        }
    }


    private synchronized void removeDeletedTemplates() {
        allTemplates.removeIf(t -> t.getDeleted_at() != null);
    }

    private synchronized void orderAllTemplates() {
        List<Template> toOrder = new ArrayList<>(allTemplates);
        toOrder.sort(Comparator.comparing(Template::getTitle));
        allTemplates = new HashSet<>(toOrder);
    }

    private synchronized void saveTemplatesLocally() {
        this.orderAllTemplates();
        String templatesPayload = new Gson().toJson(allTemplates);
        if (!templatesPayload.equals(callbacks.loadExtensionSetting(CONVISO_ALL_TEMPLATES))) {
            callbacks.saveExtensionSetting(CONVISO_ALL_TEMPLATES, templatesPayload);
            util.sendStdout("Saved templates locally.");
        } else {
            util.sendStdout("Saved tempaltes are up to date.");
        }
    }

    private synchronized void loadLocalTemplates() {
        String templatesPayload = callbacks.loadExtensionSetting(CONVISO_ALL_TEMPLATES);
        if (templatesPayload != null && !templatesPayload.equals(new Gson().toJson(allTemplates))) {
            allTemplates = new HashSet<>(Arrays.asList(new Gson().fromJson(templatesPayload, Template[].class)));
            util.sendStdout("Loaded templates from local.");
            this.alreadyLoaded = true;
        } else {
            util.sendStdout("Local templates are equal to memory templates.");
        }
    }


    private void getAllTemplatesByCompanyId() {
        Integer companyId = getCompanyIdSetting();
        if (companyId == null) {
            util.sendStderr("Company ID not defined. Please fill it in Settings.");
            return;
        }
        this.allTemplates = new HashSet<>();
        getAllVulnerabilitiesModelsFromApi(companyId);
        this.orderAllTemplates();
    }

    private Integer getCompanyIdSetting() {
        String rawCompanyId = callbacks.loadExtensionSetting(CONVISO_COMPANY_ID);
        if (rawCompanyId == null || rawCompanyId.trim().isEmpty()) {
            return null;
        }
        try {
            return Integer.parseInt(rawCompanyId.trim());
        } catch (NumberFormatException ex) {
            return null;
        }
    }


}
