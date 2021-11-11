package models.graphql;

import com.google.gson.JsonObject;

import java.util.Arrays;

public class GraphQLErrors {
    private JsonObject[] errors;


    public JsonObject[] getErrors() {
        return errors;
    }

    public void setErrors(JsonObject[] errors) {
        this.errors = errors;
    }

    @Override
    public String toString() {
        return "GraphQLErrors{" +
                "errors=" + Arrays.toString(errors) +
                '}';
    }
}
