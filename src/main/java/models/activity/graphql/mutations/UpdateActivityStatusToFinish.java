package models.activity.graphql.mutations;


import models.attachments.AttachmentArchive;
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
    AttachmentArchive attachmentArchive;

    public UpdateActivityStatusToFinish(int activityId, String textEvidence) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusWithReason, activityId, "DONE", Util.jsonSafeString(textEvidence)));
    }

    public UpdateActivityStatusToFinish(int activityId, AttachmentArchive archiveAttachment) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusWithArchive, activityId, "DONE"));
        this.attachmentArchive = archiveAttachment;
    }

    public UpdateActivityStatusToFinish(int activityId, AttachmentArchive archiveAttachment, String textEvidence) {
        this.setQuery(String.format(GraphQLMutations.mutationUpdateActivityStatusWithArchiveAndReason, activityId, "DONE", Util.jsonSafeString(textEvidence)));
        this.attachmentArchive = archiveAttachment;
    }


    public HttpEntity getHttpEntity() throws FileNotFoundException {

        MultipartEntityBuilder multipartEntityBuilder = MultipartEntityBuilder.create();
        multipartEntityBuilder.addTextBody("operations", this.getQuery());
        multipartEntityBuilder.addTextBody("map", "{\"0\":[\"variables.archives.0\"]}");

        File file = new File(this.attachmentArchive.getPath());

        try {
            multipartEntityBuilder.addBinaryBody("0", new FileInputStream(file), ContentType.parse(Files.probeContentType(Path.of(file.getPath()))), Util.removeSpecialCharacters(this.attachmentArchive.getName()));
        } catch (IOException ioException) {
            multipartEntityBuilder.addBinaryBody("0", new FileInputStream(file), ContentType.APPLICATION_OCTET_STREAM, Util.removeSpecialCharacters(this.attachmentArchive.getName()));
        }

        return multipartEntityBuilder.build();
    }


}
