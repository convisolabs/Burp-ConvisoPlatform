package services;

import burp.*;
import utilities.Util;
import com.google.gson.*;
import http.HttpClient;
import models.vulnerability.Template;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;


public class TemplateService {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private Template[] allTemplates;
    private final Util util;
    private static final String FLOW_ALL_TEMPLATES = "FLOW.ALL.TEMPLATES";
    private Calendar lastRequestTime;
    private static boolean loadedTemplates;


    public TemplateService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
        loadedTemplates = false;
    }

    public Template[] getAllTemplates(){
        if(loadedTemplates && (lastRequestTime == null || (System.currentTimeMillis() - lastRequestTime.getTimeInMillis()) > 30000)){
            getAllVulnerabilitiesModels();
        }else{
            checkTemplates();
        }
        return this.allTemplates;
    }

    private void checkTemplates(){
        loadLocalTemplates();
        if(!loadedTemplates) {
            getAllVulnerabilitiesModels();
            loadedTemplates = true;
        }else if(loadedTemplates && lastRequestTime == null){
            new Thread(this::getAllVulnerabilitiesModels).start();
        }

    }

    /* Buscar os templates da API */
    private Template[] getAllVulnerabilitiesModels(){
        Template[] templatesArray = new Template[0];
        HttpClient httpClient = new HttpClient(this.callbacks, this.helpers);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("per_page", "1000");

        String httpResult = httpClient.get("v3/company/11/vulnerability_templates", parameters);

        IResponseInfo responseCleaned = helpers.analyzeResponse(helpers.stringToBytes(httpResult));
        String jsonResponse = httpResult.substring(responseCleaned.getBodyOffset());
        try{
            templatesArray = new Gson().fromJson(jsonResponse, Template[].class);
            this.sanitizeTemplates(templatesArray);
            util.sendStdout("[Re]Loaded templates from API.");
        }catch (com.google.gson.JsonSyntaxException e) {
            util.sendStderr(jsonResponse);
            return new Template[0];
        }catch (Exception e){
            util.sendStderr("Error loading templates.");
            return new Template[0];
        }
        this.allTemplates = templatesArray;
        this.saveTemplatesLocally();
        this.lastRequestTime = Calendar.getInstance();
        return this.allTemplates;
    }

    public Template getTemplateByTitle(String templateTitle){
        if(loadedTemplates){
            for (Template t : this.allTemplates) {
                if(t.getTitle().equals(templateTitle)){
                    return t;
                }
            }
        }
        return null;
    }

    public int getTemplateIdByTitle(String templateTitle){
        if(this.allTemplates != null && this.allTemplates.length > 0){
            return this.getTemplateByTitle(templateTitle).getId();
        }else{
            return 0;
        }

    }
    
    private void sanitizeTemplates(Template[] templatesToSanitize){
        for (Template t : templatesToSanitize) {
            t.sanitizeTemplate();
        }
    }

    private void saveTemplatesLocally(){
        String templatesPayload = new Gson().toJson(allTemplates);
        if(!templatesPayload.equals(callbacks.loadExtensionSetting(FLOW_ALL_TEMPLATES))){
            callbacks.saveExtensionSetting(FLOW_ALL_TEMPLATES, templatesPayload);
            util.sendStdout("Saved templates locally.");
        }
    }

    private void loadLocalTemplates(){
        String templatesPayload = callbacks.loadExtensionSetting(FLOW_ALL_TEMPLATES);
        if(templatesPayload != null){
            allTemplates = new Gson().fromJson(templatesPayload, Template[].class);
            util.sendStdout("Loaded templates from local.");
            loadedTemplates = true;
        }

    }

}
