package models.activity.graphql.mutations;

import models.graphql.mutation.GraphQLMutations;

public class UpdateActivityStatusToNotApply extends UpdateActivityStatus{

    public UpdateActivityStatusToNotApply(int activityId, String justification) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusToNotApply, activityId, justification));
    }
}
