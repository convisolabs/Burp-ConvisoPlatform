package models.project.graphql;

import models.graphql.GraphQLResponse;
import models.project.Project;

import java.util.Arrays;

public class AllocatedAnalysisQL extends GraphQLResponse {

    private Project[] collection;

    public Project[] getCollection() {
        return collection;
    }

    public void setCollection(Project[] collection) {
        this.collection = collection;
    }
    
    public void sanitizeProjects(){
        for (Project p :
                collection) {
            p.sanitize();
        }
    }

    @Override
    public String toString() {
        return "AllocatedProjectsQL{" +
                "data=" + data +
                ", metadata=" + metadata +
                ", collection=" + Arrays.toString(collection) +
                '}';
    }
}
