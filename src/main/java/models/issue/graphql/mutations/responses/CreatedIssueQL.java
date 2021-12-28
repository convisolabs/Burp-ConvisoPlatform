package models.issue.graphql.mutations.responses;

import com.google.gson.JsonObject;

import java.util.Arrays;

public class CreatedIssueQL {

    String[] errors;
    JsonObject issue;

    public String[] getErrors() {
        return errors;
    }

    public JsonObject getVulnerabilityReturned() {
        return issue;
    }

    @Override
    public String toString() {
        return "CreatedIssueQL{" +
                "errors=" + Arrays.toString(errors) +
                ", vulnerabilityReturned=" + issue.toString() +
                '}';
    }

    public String getJoinedErrors(){
        return String.join("\n", this.errors);
    }
}
