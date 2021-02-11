package models.project;

public class Project {

    private int id;
    private String pid;
    private String label;
    private String description;
    private String project_type;
    private String start_date;
    private String end_date;
    private int contracted_hours;
    private String scope;
    private boolean is_public;
    private boolean is_open;
    private String language;
    private String project_status;
    private String auditing;
    private boolean continuous_delivery;
    private String planned_started_at;
    private String estimated_hours;
    private String retested_at;
    private boolean free_retest;
    private String last_project_status;
    private boolean environment_invaded;
    private String hours_or_days;
    private String estimated_days;
    private String api_code;
    private String repository_url;
    private String executive_summary;
    private String main_recommendations;
    private int vulnerabilities_count;
    private String[] teams;
    private String microservice_folder;
    private int students;
    private boolean integration_deploy;
    private boolean receive_deploys;
    private boolean close_comments;
    private int deploy_send_frequency;
    private String plan;
    private String connectivity;
    private String[] tag_list;
    private String[] tecnology_list;
    private String created_at;


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getPid() {
        return pid;
    }

    public void setPid(String pid) {
        this.pid = pid;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getProject_type() {
        return project_type;
    }

    public void setProject_type(String project_type) {
        this.project_type = project_type;
    }

    public String getStart_date() {
        return start_date;
    }

    public void setStart_date(String start_date) {
        this.start_date = start_date;
    }

    public String getEnd_date() {
        return end_date;
    }

    public void setEnd_date(String end_date) {
        this.end_date = end_date;
    }

    public int getContracted_hours() {
        return contracted_hours;
    }

    public void setContracted_hours(int contracted_hours) {
        this.contracted_hours = contracted_hours;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public boolean isIs_public() {
        return is_public;
    }

    public void setIs_public(boolean is_public) {
        this.is_public = is_public;
    }

    public boolean isIs_open() {
        return is_open;
    }

    public void setIs_open(boolean is_open) {
        this.is_open = is_open;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getProject_status() {
        return project_status;
    }

    public void setProject_status(String project_status) {
        this.project_status = project_status;
    }

    public String getAuditing() {
        return auditing;
    }

    public void setAuditing(String auditing) {
        this.auditing = auditing;
    }

    public boolean isContinuous_delivery() {
        return continuous_delivery;
    }

    public void setContinuous_delivery(boolean continuous_delivery) {
        this.continuous_delivery = continuous_delivery;
    }

    public String getPlanned_started_at() {
        return planned_started_at;
    }

    public void setPlanned_started_at(String planned_started_at) {
        this.planned_started_at = planned_started_at;
    }

    public String getEstimated_hours() {
        return estimated_hours;
    }

    public void setEstimated_hours(String estimated_hours) {
        this.estimated_hours = estimated_hours;
    }

    public String getRetested_at() {
        return retested_at;
    }

    public void setRetested_at(String retested_at) {
        this.retested_at = retested_at;
    }

    public boolean isFree_retest() {
        return free_retest;
    }

    public void setFree_retest(boolean free_retest) {
        this.free_retest = free_retest;
    }

    public String getLast_project_status() {
        return last_project_status;
    }

    public void setLast_project_status(String last_project_status) {
        this.last_project_status = last_project_status;
    }

    public boolean isEnvironment_invaded() {
        return environment_invaded;
    }

    public void setEnvironment_invaded(boolean environment_invaded) {
        this.environment_invaded = environment_invaded;
    }

    public String getHours_or_days() {
        return hours_or_days;
    }

    public void setHours_or_days(String hours_or_days) {
        this.hours_or_days = hours_or_days;
    }

    public String getEstimated_days() {
        return estimated_days;
    }

    public void setEstimated_days(String estimated_days) {
        this.estimated_days = estimated_days;
    }

    public String getApi_code() {
        return api_code;
    }

    public void setApi_code(String api_code) {
        this.api_code = api_code;
    }

    public String getRepository_url() {
        return repository_url;
    }

    public void setRepository_url(String repository_url) {
        this.repository_url = repository_url;
    }

    public String getExecutive_summary() {
        return executive_summary;
    }

    public void setExecutive_summary(String executive_summary) {
        this.executive_summary = executive_summary;
    }

    public String getMain_recommendations() {
        return main_recommendations;
    }

    public void setMain_recommendations(String main_recommendations) {
        this.main_recommendations = main_recommendations;
    }

    public int getVulnerabilities_count() {
        return vulnerabilities_count;
    }

    public void setVulnerabilities_count(int vulnerabilities_count) {
        this.vulnerabilities_count = vulnerabilities_count;
    }

    public String[] getTeams() {
        return teams;
    }

    public void setTeams(String[] teams) {
        this.teams = teams;
    }

    public String getMicroservice_folder() {
        return microservice_folder;
    }

    public void setMicroservice_folder(String microservice_folder) {
        this.microservice_folder = microservice_folder;
    }

    public int getStudents() {
        return students;
    }

    public void setStudents(int students) {
        this.students = students;
    }

    public boolean isIntegration_deploy() {
        return integration_deploy;
    }

    public void setIntegration_deploy(boolean integration_deploy) {
        this.integration_deploy = integration_deploy;
    }

    public boolean isReceive_deploys() {
        return receive_deploys;
    }

    public void setReceive_deploys(boolean receive_deploys) {
        this.receive_deploys = receive_deploys;
    }

    public boolean isClose_comments() {
        return close_comments;
    }

    public void setClose_comments(boolean close_comments) {
        this.close_comments = close_comments;
    }

    public int getDeploy_send_frequency() {
        return deploy_send_frequency;
    }

    public void setDeploy_send_frequency(int deploy_send_frequency) {
        this.deploy_send_frequency = deploy_send_frequency;
    }

    public String getPlan() {
        return plan;
    }

    public void setPlan(String plan) {
        this.plan = plan;
    }

    public String getConnectivity() {
        return connectivity;
    }

    public void setConnectivity(String connectivity) {
        this.connectivity = connectivity;
    }

    public String[] getTag_list() {
        return tag_list;
    }

    public void setTag_list(String[] tag_list) {
        this.tag_list = tag_list;
    }

    public String[] getTecnology_list() {
        return tecnology_list;
    }

    public void setTecnology_list(String[] tecnology_list) {
        this.tecnology_list = tecnology_list;
    }

    public String getCreated_at() {
        return created_at;
    }

    public void setCreated_at(String created_at) {
        this.created_at = created_at;
    }
}
