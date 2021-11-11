package models.graphql.query;

public class GraphQLQueries {

    static int actualPage = 1;
    static int limit = 1000;


    public final static String getAllocatedProjectsQuery = "query{ allocatedProjects(page: " + actualPage + ", limit: " + limit + "){ collection{ id companyId label pid dueDate activities{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt } } } }";
    public final static String getVulnerabilitiesTemplatesByCompany = "query{ vulnerabilitiesTemplatesByCompanyId(id: %1$d, page: " + actualPage + ", limit: " + limit + "){ collection{  id title description reference solution impact probability notification impactResume deletedAt}}}";
    public final static String getProjectById = "query{ project(id: %1$d){ id companyId label pid activities{ id archiveFilename evidenceText justify portalUser{ name } status title updatedAt }}}";
    public final static String testAPIKey = "query{ allocatedProjects(page: " + 1 + ", limit: " + 1 + "){ collection{id} } }";


}
