package models.graphql;


import models.vulnerability.Evidence;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import utilities.Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

public class GraphQLMutation {

    protected String query;

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }



    //    public HttpEntity notificationToMultipart() throws FileNotFoundException {
//        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
//        builder.addTextBody("vulnerability[project_id]", this.analysisId +"");
//        builder.addTextBody("vulnerability[vulnerability_model_id]", this.vulnerabilityTemplateId +"");
//        builder.addTextBody("vulnerability[notification_type]", "true");
//        builder.addTextBody("vulnerability[client_impact]", this.description);
//
//        for (Evidence e :
//                this.vulnerabilityArchives) {
//            File file = new File(e.getPath());
//            builder.addBinaryBody("vulnerability[vulnerability_archives_attributes][][archive]",new FileInputStream(file), ContentType.APPLICATION_OCTET_STREAM, Util.removeSpecialCharacters(e.getName()));
//        }
//        return builder.build();
//    }
//
//    public HttpEntity vulnerabilityToMultipart() throws FileNotFoundException {
//        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
//        builder.addTextBody("vulnerability[vulnerability_model_id]", this.vulnerabilityTemplateId +"");
//        builder.addTextBody("vulnerability[impact]", this.impact);
//        builder.addTextBody("vulnerability[probability]", this.probability);
//        builder.addTextBody("vulnerability[client_impact]", this.description);
//        builder.addTextBody("vulnerability[impact_resume]", this.impactResume);
//        builder.addTextBody("vulnerability[web_protocol]", this.webProtocol);
//        builder.addTextBody("vulnerability[web_method]", this.webMethod);
//        builder.addTextBody("vulnerability[web_url]", this.webUrl);
//        builder.addTextBody("vulnerability[web_steps]", this.webSteps);
//        builder.addTextBody("vulnerability[web_request]", this.webRequest);
//        builder.addTextBody("vulnerability[parameters]", this.webParameters);
//        builder.addTextBody("vulnerability[web_response]", this.webResponse);
//        builder.addTextBody("vulnerability[project_id]", this.analysisId +"");
//
//
//        if(this.invaded){
//            builder.addTextBody("vulnerability[invaded]", "1");
//            builder.addTextBody("vulnerability[invaded_environment_description]", this.invadedEnvironmentDescription);
//        }else{
//            builder.addTextBody("vulnerability[invaded]", "0");
//        }
//
//        for (Evidence e :
//                this.vulnerabilityArchives) {
//            File file = new File(e.getPath());
//            builder.addBinaryBody("vulnerability[vulnerability_archives_attributes][][archive]",new FileInputStream(file), ContentType.APPLICATION_OCTET_STREAM, Util.removeSpecialCharacters(e.getName()));
//        }
//        return builder.build();
//    }


}
