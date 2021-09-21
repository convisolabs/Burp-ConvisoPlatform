package models.activity.graphql.mutations;


import models.evidences.EvidenceArchive;
import models.graphql.mutation.GraphQLMutations;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import utilities.Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class UpdateActivityStatusToFinish extends UpdateActivityStatus{
    EvidenceArchive evidenceArchive;

    public UpdateActivityStatusToFinish(int activityId, String textEvidence) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusToFinishWithTextEvidence, activityId, textEvidence));
    }

    public UpdateActivityStatusToFinish(int activityId, EvidenceArchive archiveEvidence) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusToFinishWithArchiveEvidence, activityId));
        this.evidenceArchive = archiveEvidence;
    }

    public UpdateActivityStatusToFinish(int activityId, EvidenceArchive archiveEvidence, String textEvidence) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusToFinishWithArchiveEvidenceAndTextEvidence, activityId, textEvidence));
        this.evidenceArchive = archiveEvidence;
    }


    public HttpEntity getHttpEntity() throws FileNotFoundException {

        MultipartEntityBuilder multipartEntityBuilder = MultipartEntityBuilder.create();
        multipartEntityBuilder.addTextBody("operations", this.getQuery());
        multipartEntityBuilder.addTextBody("map", "{\"0\":[\"variables.evidenceArchive\"]}");

        File file = new File(this.evidenceArchive.getPath());

        try {
            multipartEntityBuilder.addBinaryBody("0", new FileInputStream(file), ContentType.parse(Files.probeContentType(Path.of(file.getPath()))), Util.removeSpecialCharacters(this.evidenceArchive.getName()));
        } catch (IOException ioException) {
            multipartEntityBuilder.addBinaryBody("0", new FileInputStream(file), ContentType.APPLICATION_OCTET_STREAM, Util.removeSpecialCharacters(this.evidenceArchive.getName()));
        }

        return multipartEntityBuilder.build();
    }


}
