package models.issue;

import com.google.gson.JsonObject;
import models.evidences.EvidenceArchive;

import java.util.ArrayList;

public class Issue {

    private int projectId;//": 2188,                   //OBRIGATORIO
    private int vulnerabilityTemplateId;//": 1,          //OBRIGATORIO

    private String impact;//": "medium",                //OBRIGATORIO
    private String probability;//": "medium",           //OBRIGATORIO

    private String description;//": "client_impact",  //OBRIGATORIO
    private String impactResume;//": "impact resume", "
    private boolean notification;

    private String webProtocol;//": "",
    private String webMethod;//": "",
    private String webUrl;//": "",
    private String webParameters;//": "",
    private String webSteps;//": "",
    private String webRequest;//": "",
    private String webResponse;//": "",
    private Boolean invaded;//": true
    private String invadedEnvironmentDescription;//": "invaded environment description",
    private ArrayList<EvidenceArchive> evidenceArchives;
    private String clienteMutationId; // added on migration to graphql



    public Issue(){

    }

    public Issue(int projectId, int vulnerabilityTemplateId, String impact, String probability, Boolean invaded,
                 String invadedDescription, String description, String impactResume, String webProtocol,
                 String webMethod, String webUrl, String webParameters,
                 String webSteps, String webRequest, String webResponse) {

        this.projectId = projectId;
        this.vulnerabilityTemplateId = vulnerabilityTemplateId;
        this.impact = impact;
        this.probability = probability;
        this.description = description;
        this.impactResume = impactResume;
        this.webProtocol = webProtocol;
        this.webMethod = webMethod;
        this.webUrl = webUrl;
        this.webParameters = webParameters;
        this.webSteps = webSteps;
        this.webRequest = webRequest;
        this.webResponse = webResponse;
        this.invaded = invaded;
        this.invadedEnvironmentDescription = invadedDescription;
        this.evidenceArchives = new ArrayList<>();
    }

    public void setProjectId(int projectId) {
        this.projectId = projectId;
    }

    public void setVulnerabilityTemplateId(int vulnerabilityTemplateId) {
        this.vulnerabilityTemplateId = vulnerabilityTemplateId;
    }

    public void setImpact(String impact) {
        this.impact = impact;
    }

    public void setProbability(String probability) {
        this.probability = probability;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setImpactResume(String impactResume) {
        this.impactResume = impactResume;
    }

    public void setWebProtocol(String webProtocol) {
        this.webProtocol = webProtocol;
    }

    public void setWebMethod(String webMethod) {
        this.webMethod = webMethod;
    }

    public void setWebUrl(String webUrl) {
        this.webUrl = webUrl;
    }

    public void setWebParameters(String webParameters) {
        this.webParameters = webParameters;
    }

    public void setWebSteps(String webSteps) {
        this.webSteps = webSteps;
    }

    public void setWebRequest(String webRequest) {
        this.webRequest = webRequest;
    }

    public void setWebResponse(String webResponse) {
        this.webResponse = webResponse;
    }


    public void setInvaded(Boolean invaded) {
        this.invaded = invaded;
    }

    public void setInvadedEnvironmentDescription(String invadedEnvironmentDescription) {
        this.invadedEnvironmentDescription = invadedEnvironmentDescription;
    }

    public void setEvidences(ArrayList<EvidenceArchive> evidenceArchives) {
        this.evidenceArchives = evidenceArchives;
    }

    public String getNullByEvidencesListSize(){
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < this.evidenceArchives.size(); i++) {
            stringBuilder.append("null");
            if(i != this.evidenceArchives.size()-1) {
                stringBuilder.append(",");
            }
        }
        return stringBuilder.toString();
    }


    public void setNotification(boolean notification) {
        this.notification = notification;
    }



//    public HttpEntity toMultipart() throws FileNotFoundException {
//        if(this.notification){
//             return this.notificationToMultipart();
//        }else{
//            return this.vulnerabilityToMultipart();
//        }
//    }


    public int getProjectId() {
        return projectId;
    }

    public int getVulnerabilityTemplateId() {
        return vulnerabilityTemplateId;
    }

    public String getImpact() {
        return impact;
    }

    public String getProbability() {
        return probability;
    }

    public String getDescription() {
        return description;
    }

    public String getImpactResume() {
        return impactResume;
    }

    public boolean isNotification() {
        return notification;
    }

    public String getWebProtocol() {
        return webProtocol;
    }

    public String getWebMethod() {
        return webMethod;
    }

    public String getWebUrl() {
        return webUrl;
    }

    public String getWebParameters() {
        return webParameters;
    }

    public String getWebSteps() {
        return webSteps;
    }

    public String getWebRequest() {
        return webRequest;
    }

    public String getWebResponse() {
        return webResponse;
    }

    public Boolean getInvaded() {
        return invaded;
    }

    public String getInvadedEnvironmentDescription() {
        return invadedEnvironmentDescription;
    }

    public ArrayList<EvidenceArchive> getEvidences() {
        return evidenceArchives;
    }

    public String getClienteMutationId() {
        return clienteMutationId;
    }

    @Override
    public String toString() {
        return "Vulnerability{" +
                "project_id=" + projectId +
                ", vulnerability_model_id=" + vulnerabilityTemplateId +
                ", impact='" + impact + '\'' +
                ", probability='" + probability + '\'' +
                ", client_impact='" + description + '\'' +
                ", impact_resume='" + impactResume + '\'' +
                ", web_protocol='" + webProtocol + '\'' +
                ", web_method='" + webMethod + '\'' +
                ", web_url='" + webUrl + '\'' +
                ", web_parameters='" + webParameters + '\'' +
                ", web_steps='" + webSteps + '\'' +
                ", web_request='" + webRequest + '\'' +
                ", web_response='" + webResponse + '\'' +
                ", invaded=" + invaded +
                ", invaded_environment_description='" + invadedEnvironmentDescription + '\'' +
                '}';
    }


    public JsonObject toJsonObject() {

        JsonObject toReturn = new JsonObject();
        toReturn.addProperty("projectId", this.projectId);
        toReturn.addProperty("vulnerabilityTemplateId", this.vulnerabilityTemplateId);
        toReturn.addProperty("impact", this.impact);
        toReturn.addProperty("probability", this.probability);
        toReturn.addProperty("description", this.description);
        toReturn.addProperty("impactResume", this.impactResume);
        toReturn.addProperty("webProtocol", this.webProtocol);
        toReturn.addProperty("webMethod", this.webMethod);
        toReturn.addProperty("webUrl", this.webUrl);
        toReturn.addProperty("webParameters", this.webParameters);
        toReturn.addProperty("webSteps", this.webSteps);
        toReturn.addProperty("webRequest", this.webRequest);
        toReturn.addProperty("webResponse", this.webResponse);
        if(this.invaded){
            toReturn.addProperty("invaded", true);
            toReturn.addProperty("invadedEnvironmentDescription", this.invadedEnvironmentDescription);
        }else{
            toReturn.addProperty("invaded", false);
        }


        return toReturn;
    }
}
