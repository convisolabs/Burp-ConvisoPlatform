package models.activity.graphql.mutations;


import models.evidences.EvidenceArchive;
import models.graphql.mutation.GraphQLMutations;

public class UpdateActivityStatusToFinish extends UpdateActivityStatus{

    public UpdateActivityStatusToFinish(int activityId, String textEvidence) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusToFinishWithTextEvidence, activityId, textEvidence));
    }

    public UpdateActivityStatusToFinish(int activityId, EvidenceArchive archiveEvidence) {

    }


}
