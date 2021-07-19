package models.activity.graphql.mutations;

import models.graphql.mutation.GraphQLMutations;

public class UpdateActivityStatusToRestart extends UpdateActivityStatus{

    public UpdateActivityStatusToRestart(int activityId) {
        this.setQuery(String.format(GraphQLMutations.mutationActivityStatusToRestart, activityId));
    }
}
