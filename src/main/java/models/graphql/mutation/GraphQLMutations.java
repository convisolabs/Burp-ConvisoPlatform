package models.graphql.mutation;

public class GraphQLMutations {

    private final String queryCreateWebVulnerabilityNotInvaded = "{\"query\": \"mutation($evidenceArchives: [Upload!]!){" +
            "createWebVulnerability(input: {" +
            "analysisId: %1$d, " +
            "vulnerabilityTemplateId: %2$d, " +
            "impact: \\\"%3$s\\\", " +
            "probability: \\\"%4$s\\\", " +
            "description: \\\"%5$s\\\", " +
            "impactResume: \\\"%6$s\\\", " +
            "webProtocol: \\\"%7$s\\\", " +
            "webMethod: \\\"%8$s\\\", " +
            "webUrl: \\\"%9$s\\\", " +
            "webParameters: \\\"%10$s\\\", " +
            "webSteps: \\\"%11$s\\\", " +
            "webRequest: \\\"%12$s\\\", " +
            "webResponse: \\\"%13$s\\\", " +
            "invaded: false, " +
            "evidenceArchives: $evidenceArchives })" +
            "{ errors vulnerability { id }}}\"," +
            "\"variables\":{\"evidenceArchives\": [%14$s]}," +
            "\"operationName\":null}";


    private final String queryCreateWebVulnerabilityInvaded = "{\"query\": \"mutation($evidenceArchives: [Upload!]!){" +
            "createWebVulnerability(input: {" +
            "analysisId: %1$d, " +
            "vulnerabilityTemplateId: %2$d, " +
            "impact: \\\"%3$s\\\", " +
            "probability: \\\"%4$s\\\", " +
            "description: \\\"%5$s\\\", " +
            "impactResume: \\\"%6$s\\\", " +
            "webProtocol: \\\"%7$s\\\", " +
            "webMethod: \\\"%8$s\\\", " +
            "webUrl: \\\"%9$s\\\", " +
            "webParameters: \\\"%10$s\\\", " +
            "webSteps: \\\"%11$s\\\", " +
            "webRequest: \\\"%12$s\\\", " +
            "webResponse: \\\"%13$s\\\", " +
            "invaded: true, " +
            "invadedEnvironmentDescription: \\\"%14$s\\\", " +
            "evidenceArchives: $evidenceArchives })" +
            "{ errors vulnerability { id }}}\"," +
            "\"variables\":{\"evidenceArchives\": [%15$s]}," +
            "\"operationName\":null}";


    private final String queryCreateNotification = "{\"query\": \"mutation($evidenceArchives: [Upload!]!){" +
            "createNotification(input: { " +
            "analysisId: %1$d, " +
            "vulnerabilityTemplateId: %2$d, " +
            "description: \\\"%3$s\\\", " +
            "evidenceArchives: $evidenceArchives " +
            "}){ clientMutationId " +
            "errors " +
            "notification{ id }}}\"," +
                    "\"variables\":{\"evidenceArchives\": [%4$s]}," +
                    "\"operationName\":null}";





    public String getQueryCreateWebVulnerabilityNotInvaded() {
        return queryCreateWebVulnerabilityNotInvaded;
    }

    public String getQueryCreateWebVulnerabilityInvaded() {
        return queryCreateWebVulnerabilityInvaded;
    }

    public String getQueryCreateNotification() {
        return queryCreateNotification;
    }
}
