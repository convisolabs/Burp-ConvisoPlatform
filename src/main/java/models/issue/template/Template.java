package models.issue.template;

import models.issue.Category;
import models.issue.Pattern;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Objects;

public class Template {
    private int id;
    private String title;
    private String description;
    private String reference;
    private String solution;
    private String impact;
    private String probability;
    private String criticity;
    private Boolean notification;
    private String created_at;
    private String updated_at;
    private Pattern[] patterns;
    private Category[] categories;
    private String impact_resume;
    private int old_id;

    private int scope_id;
    private String deleted_at;
    private String[] pattern_list;
    private String[] category_list;


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) { this.title = title; }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getReference() {
        return reference;
    }

    public void setReference(String reference) {
        this.reference = reference;
    }

    public String getSolution() {
        return solution;
    }

    public void setSolution(String solution) {
        this.solution = solution;
    }

    public String getImpact() {
        return impact;
    }

    public void setImpact(String impact) {
        this.impact = impact;
    }

    public String getProbability() {
        return probability;
    }

    public void setProbability(String probability) {
        this.probability = probability;
    }

    public String getCriticity() {
        return criticity;
    }

    public void setCriticity(String criticity) {
        this.criticity = criticity;
    }

    public String getCreated_at() {
        return created_at;
    }

    public void setCreated_at(String created_at) {
        this.created_at = created_at;
    }

    public String getUpdated_at() {
        return updated_at;
    }

    public void setUpdated_at(String updated_at) {
        this.updated_at = updated_at;
    }

    public String getImpact_resume() {
        return impact_resume;
    }

    public void setImpact_resume(String impact_resume) {
        this.impact_resume = impact_resume;
    }

    public int getOld_id() {
        return old_id;
    }

    public void setOld_id(int old_id) {
        this.old_id = old_id;
    }

    public void setPatterns(Pattern[] patterns) {
        this.patterns = patterns;
    }

    public void setCategories(Category[] categories) {
        this.categories = categories;
    }

    public Boolean getNotification() {
        return notification;
    }

    public void setNotification(Boolean notification) {
        this.notification = notification;
    }

    public int getScope_id() {
        return scope_id;
    }

    public void setScope_id(int scope_id) {
        this.scope_id = scope_id;
    }

    public String getDeleted_at() {
        return deleted_at;
    }

    public void setDeleted_at(String deleted_at) {
        this.deleted_at = deleted_at;
    }

    public Pattern[] getPatterns() {
        return patterns;
    }

    public Category[] getCategories() {
        return categories;
    }

    public String[] getPattern_list() {
        return pattern_list;
    }

    public void setPattern_list(String[] pattern_list) {
        this.pattern_list = pattern_list;
    }

    public String[] getCategory_list() {
        return category_list;
    }

    public void setCategory_list(String[] category_list) {
        this.category_list = category_list;
    }

    public String getTemplateIdAndName(){
        return this.getId()+" - "+this.getTitle();
    }

    @Override
    public String toString() {
        return this.title;
    }

    public String objectToString() {
        return "Template{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", description='" + description + '\'' +
                ", reference='" + reference + '\'' +
                ", solution='" + solution + '\'' +
                ", impact='" + impact + '\'' +
                ", probability='" + probability + '\'' +
                ", criticity='" + criticity + '\'' +
                ", created_at='" + created_at + '\'' +
                ", updated_at='" + updated_at + '\'' +
                ", patterns=" + Arrays.toString(patterns) +
                ", categories=" + Arrays.toString(categories) +
                ", impact_resume='" + impact_resume + '\'' +
                ", old_id=" + old_id +
                ", notification=" + notification +
                ", scope_id=" + scope_id +
                ", deleted_at='" + deleted_at + '\'' +
                ", pattern_list=" + Arrays.toString(pattern_list) +
                ", category_list=" + Arrays.toString(category_list) +
                '}';
    }

    public void sanitize() {
        try {
            this.setTitle(new String(this.title.getBytes("ISO-8859-1"), "UTF-8").trim() + ((this.notification) ? " - (Notification)" : ""));
            this.setDescription(new String(this.description.getBytes("ISO-8859-1"), "UTF-8").trim());
        } catch (UnsupportedEncodingException ignored) {

        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Template template = (Template) o;
        return id == template.id && scope_id == template.scope_id && title.equals(template.title);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, title, scope_id);
    }
}
