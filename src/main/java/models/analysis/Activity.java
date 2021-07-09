package models.analysis;

import models.analyst.Analyst;
import utilities.Util;

public class Activity {
    private Integer id;
    private String archiveFilename;
    private String evidenceText;
    private String justify;
    private Analyst portalUser;
    private Integer projectId;
    private String status;
    private String title;
    private String updatedAt;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getArchiveFilename() {
        return archiveFilename;
    }

    public void setArchiveFilename(String archiveFilename) {
        this.archiveFilename = archiveFilename;
    }

    public String getEvidenceText() {
        return evidenceText;
    }

    public void setEvidenceText(String evidenceText) {
        this.evidenceText = evidenceText;
    }

    public String getJustify() {
        return justify;
    }

    public void setJustify(String justify) {
        this.justify = justify;
    }

    public Integer getProjectId() {
        return projectId;
    }

    public void setProjectId(Integer projectId) {
        this.projectId = projectId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public String getPrettyUpdateAt() {
        return Util.prettifyDate(this.updatedAt);
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Analyst getPortalUser() {
        return portalUser;
    }

    public void setPortalUser(Analyst portalUser) {
        this.portalUser = portalUser;
    }
}
