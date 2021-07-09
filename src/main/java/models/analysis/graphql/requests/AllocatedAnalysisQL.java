package models.analysis.graphql.requests;

import models.analysis.Analysis;

public class AllocatedAnalysisQL {

    private Analysis[] collection;

    public Analysis[] getCollection() {
        return collection;
    }

    public void sanitizeProjects(){
        for (Analysis p :
                collection) {
            p.sanitize();
        }
    }
    
}
