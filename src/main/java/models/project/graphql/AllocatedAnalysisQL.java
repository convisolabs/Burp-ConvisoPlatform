package models.project.graphql;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import models.graphql.GraphQLResponse;
import models.project.Project;

import java.util.Arrays;

public class AllocatedAnalysisQL {

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
