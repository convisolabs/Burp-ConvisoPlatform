package models.graphql.mutation;

public class GraphQLMutations {

    public final static String mutationCreateWebVulnerabilityNotInvaded = "{\"query\": \"mutation($evidenceArchives: [Upload!]!){" +
            "createWebVulnerability(input: {" +
            "projectId: %1$d, " +
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


    public final static String mutationCreateWebVulnerabilityInvaded = "{\"query\": \"mutation($evidenceArchives: [Upload!]!){" +
            "createWebVulnerability(input: {" +
            "projectId: %1$d, " +
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


    public final static String mutationCreateNotification = "{\"query\": \"mutation($evidenceArchives: [Upload!]!){" +
            "createNotification(input: { " +
            "projectId: %1$d, " +
            "vulnerabilityTemplateId: %2$d, " +
            "description: \\\"%3$s\\\", " +
            "evidenceArchives: $evidenceArchives " +
            "}){ clientMutationId " +
            "errors " +
            "notification{ id }}}\"," +
                    "\"variables\":{\"evidenceArchives\": [%4$s]}," +
                    "\"operationName\":null}";

    public final static String mutationUpdateActivityStatusToStart = "mutation{" +
            "updateActivityStatusToStart(input: { " +
            "activityId : %1$d }){ " +
            "activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } "+
            "errors }}";


    public final static String mutationUpdateActivityStatusToFinishWithTextEvidence = "mutation{" +
            "updateActivityStatusToFinish(input: {" +
            "activityId: %1$d, " +
            "evidence: \"%2$s\" }){" +
            "activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } " +
            "errors }}";

    public final static String mutationUpdateActivityStatusToFinishWithArchiveEvidence = "{\"query\": \"mutation($evidenceArchive: Upload){" +
            "updateActivityStatusToFinish(input: {" +
            "activityId: %1$d, " +
            "evidenceArchive: $evidenceArchive })" +
            "{ activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } errors }}\", " +
            "\"variables\": { \"evidenceArchive\": null }, \"operationName\": null}";

    public final static String mutationUpdateActivityStatusToFinishWithArchiveEvidenceAndTextEvidence = "{\"query\": \"mutation($evidenceArchive: Upload){" +
            "updateActivityStatusToFinish(input: {" +
            "activityId: %1$d, " +
            "evidenceArchive: $evidenceArchive, " +
            "evidence: \\\"%2$s\\\" })" +
            "{ activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } errors }}\", " +
            "\"variables\": { \"evidenceArchive\": null }, \"operationName\": null}";

    public final static String mutationActivityStatusToRestart = "mutation{" +
            "updateActivityStatusToRestart(input: {" +
            "activityId: %1$d }){" +
            "activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } " +
            "errors }}";

    public final static String mutationUpdateActivityStatusToNotApply = "mutation{" +
            "updateActivityStatusToNotApply(input: {" +
            "activityId: %1$d " +
            "justify: \"%2$s\" }){" +
            "activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } " +
            "errors }}";

}
