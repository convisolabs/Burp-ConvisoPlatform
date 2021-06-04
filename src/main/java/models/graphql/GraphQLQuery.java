package models.graphql;

import java.util.HashMap;

public class GraphQLQuery {
    protected String query;
    protected HashMap variables;
    protected String operationName;

    public GraphQLQuery() {
    }

    public GraphQLQuery(String query) {
        this.query = query;
    }

    public GraphQLQuery(String query, HashMap variables, String operationName) {
        this.query = query;
        this.variables = variables;
        this.operationName = operationName;
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public HashMap getVariables() {
        return variables;
    }

    public void setVariables(HashMap variables) {
        this.variables = variables;
    }

    public String getOperationName() {
        return operationName;
    }

    public void setOperationName(String operationName) {
        this.operationName = operationName;
    }
}
