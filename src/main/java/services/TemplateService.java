package services;

import burp.*;
import models.services_manager.ServicesManager;
import utilities.Util;
import com.google.gson.*;
import http.HttpClient;
import models.vulnerability.Template;

import java.util.*;


public class TemplateService extends FathersService {
    private final ProjectService projectService;
    private Set<Template> allTemplates = new HashSet<>();

    private static final String FLOW_ALL_TEMPLATES = "FLOW.ALL.TEMPLATES";

    public TemplateService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
        alreadyLoaded = false;
        this.projectService = this.servicesManager.getProjectService();
    }

    public Set<Template> getAllTemplates() {
        if (this.alreadyLoaded && (this.lastRequestTime == null || (System.currentTimeMillis() - this.lastRequestTime.getTimeInMillis()) > 30000)) {
            this.projectService.verifyAllocatedProjects();
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
    private void getAllVulnerabilitiesModelsFromApi(Integer scopeId) {
        Template[] templatesArray;
        HttpClient httpClient = new HttpClient(this.callbacks, this.helpers);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("per_page", "1000");
        String httpResult = httpClient.get("v3/company/" + scopeId + "/vulnerability_templates", parameters);
        IResponseInfo responseCleaned = helpers.analyzeResponse(helpers.stringToBytes(httpResult));
        String jsonResponse = httpResult.substring(responseCleaned.getBodyOffset());
        try {
            templatesArray = new Gson().fromJson(jsonResponse, Template[].class);
            this.sanitizeTemplates(templatesArray);
            util.sendStdout("[Re]Loaded templates from API. Scope Id: " + scopeId);
            this.allTemplates.addAll(Arrays.asList(templatesArray));
            this.saveTemplatesLocally();
            this.lastRequestTime = Calendar.getInstance();
        } catch (com.google.gson.JsonSyntaxException e) {
            util.sendStderr(jsonResponse);
        } catch (Exception e) {
            util.sendStderr("Error loading templates.");
        }
    }


    private synchronized void sanitizeTemplates(Template[] templatesToSanitize) {
        for (Template t : templatesToSanitize) {
            t.sanitizeTemplate();
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
            util.sendStdout("Saved tempaltes are up to date.");
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
        for (Integer i :
                projectService.getScopeIdsOfProjects()) {
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
