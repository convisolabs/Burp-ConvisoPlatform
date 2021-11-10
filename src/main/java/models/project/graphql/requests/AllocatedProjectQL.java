package models.project.graphql.requests;

import models.project.Project;

public class AllocatedProjectQL {

    private Project[] collection;

    public Project[] getCollection() {
        return collection;
    }

    public void sanitizeProjects(){
        for (Project p :
                collection) {
            p.sanitize();
        }
    }
    
}
