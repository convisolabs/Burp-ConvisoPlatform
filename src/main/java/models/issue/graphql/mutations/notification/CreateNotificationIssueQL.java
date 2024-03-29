package models.issue.graphql.mutations.notification;

import models.graphql.mutation.GraphQLMutations;
import models.issue.Issue;
import models.issue.graphql.mutations.CreateIssueQL;

public class CreateNotificationIssueQL extends CreateIssueQL {

    public CreateNotificationIssueQL(Issue issue) {
        super(issue);
    }

    @Override
    protected void prepareQuery() {
        this.query = String.format(GraphQLMutations.mutationCreateNotification,
                this.issue.getProjectId(),
                this.issue.getVulnerabilityTemplateId(),
                this.issue.getDescription(),
                this.issue.getNullByEvidencesListSize());
    }
}
