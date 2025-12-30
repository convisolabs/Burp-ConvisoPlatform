package models.activity.graphql.mutations;

import models.graphql.mutation.GraphQLMutations;

public class UpdateActivityStatusToStart extends UpdateActivityStatus{

    public UpdateActivityStatusToStart(int activityId) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatus, activityId, "IN_PROGRESS"));
    }
}
