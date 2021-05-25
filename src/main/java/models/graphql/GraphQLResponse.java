package models.graphql;

public class GraphQLResponse {
    protected Object data;
    protected Metadata metadata;

    public Metadata getMetadata() {
        return metadata;
    }

    public void setMetadata(Metadata metadata) {
        this.metadata = metadata;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    @Override
    public String toString() {
        return "GraphQLResponse{" +
                "data=" + data +
                '}';
    }
}
