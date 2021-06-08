package models.graphql;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import models.project.graphql.AllocatedAnalysisQL;

public class GraphQLResponse {
    protected String data;
    protected Metadata metadata;
    protected JsonObject contentOfData;


    public GraphQLResponse(String data) {
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

    public void prepareContentOfData(){
        this.contentOfData = (JsonObject) (new Gson().fromJson(this.data.toString(), JsonObject.class)).get("data");
    }

    public JsonObject getContentOfData(String key) {
        return (JsonObject) contentOfData.get(key);
    }

    public void setContentOfData(JsonObject contentOfData) {
        this.contentOfData = contentOfData;
    }

    //    public getProperty(){
//
//
//        gson.fromJson(().get("allocatedAnalyses"), AllocatedAnalysisQL.class);
//    }

    @Override
    public String toString() {
        return "GraphQLResponse{" +
                "data=" + data +
                '}';
    }
}
