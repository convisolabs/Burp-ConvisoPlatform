package models.graphql;

import com.google.gson.JsonObject;

public class GraphQLErrors {
    private JsonObject[] errors;


    public JsonObject[] getErrors() {
        return errors;
    }

    public void setErrors(JsonObject[] errors) {
        this.errors = errors;
    }
}
