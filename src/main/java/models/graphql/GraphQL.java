package models.graphql;

import java.util.HashMap;

public class GraphQL {
    private String query;
    private HashMap variables;
    private String operationName;

    public GraphQL() {
    }

    public GraphQL(String query) {
        this.query = query;
    }

    public GraphQL(String query, HashMap variables, String operationName) {
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
