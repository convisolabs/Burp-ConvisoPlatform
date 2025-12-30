package models.graphql.mutation;

public class GraphQLMutations {

    public final static String mutationCreateWebVulnerability = "mutation{" +
            "createWebVulnerability(input: {%1$s})" +
            "{ issue { id title }}}";

    public final static String mutationUpdateActivityStatus = "mutation{" +
            "updateActivityStatus(input: { " +
            "id : %1$d, " +
            "status: %2$s }){ " +
            "activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } " +
            "errors }}";

    public final static String mutationUpdateActivityStatusWithReason = "mutation{" +
            "updateActivityStatus(input: { " +
            "id : %1$d, " +
            "status: %2$s, " +
            "reason: \"%3$s\" }){ " +
            "activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } " +
            "errors }}";

    public final static String mutationUpdateActivityStatusWithArchive = "{\"query\": \"mutation($archives: [Upload!]!){" +
            "updateActivityStatus(input: { " +
            "id : %1$d, " +
            "status: %2$s, " +
            "archives: $archives }){ " +
            "activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } " +
            "errors }}\", " +
            "\"variables\": { \"archives\": [null] }, \"operationName\": null}";

    public final static String mutationUpdateActivityStatusWithArchiveAndReason = "{\"query\": \"mutation($archives: [Upload!]!){" +
            "updateActivityStatus(input: { " +
            "id : %1$d, " +
            "status: %2$s, " +
            "reason: \\\"%3$s\\\", " +
            "archives: $archives }){ " +
            "activity{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } " +
            "errors }}\", " +
            "\"variables\": { \"archives\": [null] }, \"operationName\": null}";

}
