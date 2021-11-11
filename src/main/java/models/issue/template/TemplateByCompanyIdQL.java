package models.issue.template;

public class TemplateByCompanyIdQL {

    private Template[] collection;

    public Template[] getCollection() {
        return collection;
    }

    public void setCollection(Template[] collection) {
        this.collection = collection;
    }

    public void sanitizeTemplates(){
        for (Template t :
                collection) {
            t.sanitize();
        }
    }
}
