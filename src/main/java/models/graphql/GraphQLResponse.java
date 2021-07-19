package models.graphql;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;

public class GraphQLResponse {
    protected String data;
    protected Metadata metadata;
    protected JsonObject contentOfData;
    protected GraphQLErrors errors;


    public GraphQLResponse(String data) throws JsonSyntaxException, Error{
        this.data = data;
        this.prepareContentOfData();
    }

    public Metadata getMetadata() {
        return metadata;
    }

    public void setMetadata(Metadata metadata) {
        this.metadata = metadata;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public void prepareContentOfData() throws JsonSyntaxException {
        this.contentOfData = (JsonObject) (new Gson().fromJson(this.data, JsonObject.class)).get("data");
        this.errors = new Gson().fromJson(this.data, GraphQLErrors.class);
        if(this.errors.getErrors() != null && this.errors.getErrors().length > 0){
            throw new Error(this.errors.toString());
        }
    }

    public JsonObject getContentOfData(String key) {
        return (JsonObject) contentOfData.get(key);
    }

    @Override
    public String toString() {
        return "GraphQLResponse{" +
                "data=" + data +
                '}';
    }
}
