package models.activity.graphql.mutations;

import models.graphql.mutation.GraphQLMutations;
import utilities.Util;

public class UpdateActivityStatusToNotApply extends UpdateActivityStatus{

    public UpdateActivityStatusToNotApply(int activityId, String justification) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusWithReason, activityId, "NOT_APPLICABLE", Util.jsonSafeString(justification)));
    }
}
