package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import models.asset.Asset;
import models.graphql.GraphQLQuery;
import models.graphql.GraphQLResponse;
import models.graphql.query.GraphQLQueries;
import models.project.Project;
import models.services_manager.ServicesManager;
import org.apache.http.auth.AuthenticationException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class AssetService extends Service {

    public AssetService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager) {
        super(callbacks, helpers, servicesManager);
    }

    public Set<Asset> getAssetsByProjectId(int projectId) throws AuthenticationException {
        String content = null;
        try {
            GraphQLService graphQLService = this.servicesManager.getGraphQLService();
            HashMap<String, Object> variables = new HashMap<>();
            variables.put("id", projectId);

            GraphQLQuery graphQLQuery = new GraphQLQuery(GraphQLQueries.getProjectAssetsById, variables, "project");
            content = graphQLService.executeQuery(graphQLQuery);
            GraphQLResponse graphQLResponse = new GraphQLResponse(content);
            Project project = new Gson().fromJson(graphQLResponse.getContentOfData("project"), Project.class);
            if (project == null || project.getAssets() == null) {
                return new HashSet<>();
            }
            for (Asset asset : project.getAssets()) {
                asset.sanitize();
            }
            Set<Asset> assets = new HashSet<>(Arrays.asList(project.getAssets()));
            util.sendStdout("Loaded assets by project ID: " + projectId + ". Count: " + assets.size());
            return assets;
        } catch (AuthenticationException e) {
            throw e;
        } catch (Error e) {
            util.sendStderr("GraphQL error loading assets by project.");
            util.sendStderr(e.toString());
            util.sendStderr(content);
            return new HashSet<>();
        } catch (Exception e) {
            util.sendStderr("Error loading assets by project.");
            util.sendStderr(content);
            return new HashSet<>();
        }
    }
}
