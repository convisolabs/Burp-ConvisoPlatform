package models.graphql.query;

public class GraphQLQueries {

    private int actualPage = 1;
    private int limit = 1000;

    private final String getAllocatedAnalysesQuery = "query{ allocatedAnalyses(page: " + actualPage + ", limit: " + limit + "){ collection{ id companyId label pid dueDate activities{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } } } }";
    private final String getVulnerabilitiesTemplatesByCompany = "query{ vulnerabilitiesTemplatesByCompanyId(id: %1$d, page: " + actualPage + ", limit: " + limit + "){ collection{  id title     description reference solution impact probability notification impactResume deletedAt}}}";

    public String getGetAllocatedAnalysesQuery() {
        return getAllocatedAnalysesQuery;
    }

    public String getGetVulnerabilitiesTemplatesByCompany() {
        return getVulnerabilitiesTemplatesByCompany;
    }
}
