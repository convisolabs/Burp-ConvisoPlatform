package models.issue.graphql.mutations;

import com.google.gson.Gson;
import models.graphql.GraphQLMutation;
import models.evidences.EvidenceArchive;
import models.issue.Issue;
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
import java.util.ArrayList;
import java.util.HashMap;

public abstract class CreateIssueQL extends GraphQLMutation {

    protected final Issue issue;
    protected String archivesMap;

    public CreateIssueQL(Issue issue) {
        this.issue = issue;
    }

    protected abstract void prepareQuery();

    protected void prepareArchivesMap() {
        HashMap<String, ArrayList<String>> mapArchives = new HashMap<>();
        for (int i = 0; i < this.issue.getEvidences().size(); i++) {
            ArrayList<String> neededEncapsulation = new ArrayList<>();
            neededEncapsulation.add("variables.evidenceArchives." + i);
            mapArchives.put(String.valueOf(i), neededEncapsulation);
        }

        this.archivesMap = new Gson().toJson(mapArchives);
    }

    public HttpEntity getHttpEntity() throws FileNotFoundException {
        this.prepareQuery();
        this.prepareArchivesMap();

        MultipartEntityBuilder multipartEntityBuilder = MultipartEntityBuilder.create();
        multipartEntityBuilder.addTextBody("operations", this.query);
        multipartEntityBuilder.addTextBody("map", this.archivesMap);


        for (int i = 0; i < issue.getEvidences().size(); i++) {
            EvidenceArchive e = issue.getEvidences().get(i);
            File file = new File(e.getPath());

            try {
                multipartEntityBuilder.addBinaryBody(String.valueOf(i), new FileInputStream(file), ContentType.parse(Files.probeContentType(Path.of(file.getPath()))), Util.removeSpecialCharacters(e.getName()));
            } catch (IOException ioException) {
                multipartEntityBuilder.addBinaryBody(String.valueOf(i), new FileInputStream(file), ContentType.APPLICATION_OCTET_STREAM, Util.removeSpecialCharacters(e.getName()));
            }

        }

        return multipartEntityBuilder.build();
    }
}
