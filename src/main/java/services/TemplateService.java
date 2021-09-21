package services;

import burp.*;
import models.graphql.GraphQLResponse;
import models.graphql.query.GraphQLQueries;
import models.services_manager.ServicesManager;
import com.google.gson.*;
import models.issue.template.Template;
import models.issue.template.TemplateByCompanyIdQL;
import org.apache.http.auth.AuthenticationException;

import java.util.*;


public class TemplateService extends Service {
    private final AnalysisService analysisService;
    private Set<Template> allTemplates = new HashSet<>();

    private static final String FLOW_ALL_TEMPLATES = "FLOW.ALL.TEMPLATES";

    public TemplateService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
        alreadyLoaded = false;
        this.analysisService = this.servicesManager.getAnalysisService();
    }

    public Set<Template> getAllTemplates() {
        if (this.alreadyLoaded && (this.lastRequestTime == null || (System.currentTimeMillis() - this.lastRequestTime.getTimeInMillis()) > 30000)) {
            this.analysisService.getAllocatedProjects();
            this.allTemplates = new HashSet<>();
            this.getAllTemplatesByScopeIds();
        } else {
            loadLocalTemplates();
            if (!this.alreadyLoaded) { // tried to load from local, but nothing was found.
                this.getAllTemplatesByScopeIds();
                this.alreadyLoaded = true;
            }
        }
        this.removeDeletedTemplates();
        return this.allTemplates;
    }

    /* Buscar os templates da API */
    private void getAllVulnerabilitiesModelsFromApi(Integer companyId) {

        String content = null;
        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            content = graphQLService.executeQuery(String.format(GraphQLQueries.getVulnerabilitiesTemplatesByCompany, companyId));
            GraphQLResponse graphQLResponse = new GraphQLResponse(content);
            TemplateByCompanyIdQL templateByCompanyIdQL = new Gson().fromJson(graphQLResponse.getContentOfData("vulnerabilitiesTemplatesByCompanyId"), TemplateByCompanyIdQL.class);
//                    gson.fromJson(((JsonObject) (gson.fromJson(content, JsonObject.class)).get("data")).get("vulnerabilitiesTemplatesByCompanyId"), TemplateByCompanyIdQL.class);
            templateByCompanyIdQL.sanitizeTemplates();
            this.allTemplates.addAll(Arrays.asList(templateByCompanyIdQL.getCollection()));
            this.saveTemplatesLocally();
            util.sendStdout("[Re]Loaded templates from API. Scope Id: " + companyId);
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
        if (!templatesPayload.equals(callbacks.loadExtensionSetting(FLOW_ALL_TEMPLATES))) {
            callbacks.saveExtensionSetting(FLOW_ALL_TEMPLATES, templatesPayload);
            util.sendStdout("Saved templates locally.");
        } else {
            util.sendStdout("Saved templates are up to date.");
        }
    }

    private synchronized void loadLocalTemplates() {
        String templatesPayload = callbacks.loadExtensionSetting(FLOW_ALL_TEMPLATES);
        if (templatesPayload != null && !templatesPayload.equals(new Gson().toJson(allTemplates))) {
            allTemplates = new HashSet<>(Arrays.asList(new Gson().fromJson(templatesPayload, Template[].class)));
            util.sendStdout("Loaded templates from local.");
            this.alreadyLoaded = true;
        } else {
            util.sendStdout("Local templates are equal to memory templates.");
        }
    }


    private void getAllTemplatesByScopeIds() {
        ArrayList<Thread> threadArrayList = new ArrayList<>();
        this.allTemplates = new HashSet<>();
        for (Integer i :
                analysisService.getScopeIdsOfProjects()) {
            Thread t = new Thread(() -> getAllVulnerabilitiesModelsFromApi(i));
            threadArrayList.add(t);
            t.start();
        }

        for (Thread tt :
                threadArrayList) {
            try {
                tt.join();
            } catch (InterruptedException ignored) {
            }
        }
        this.orderAllTemplates();
    }


}
