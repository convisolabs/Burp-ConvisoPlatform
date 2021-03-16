package view.context_menu.listeners;

import burp.*;
import models.vulnerability.Evidence;
import services.TemplateService;
import utilities.Util;
import view.new_vulnerability.NewVulnerabilityTab;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ContextMenuActionListener implements ActionListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private TemplateService templateService;
    private IContextMenuInvocation invocation;
    private Util util;
    private final NewVulnerabilityTab newVulnerabilityTab;
    String requestHeader = "/* \n * REQUEST \n */\n\n";
    String responseHeader = "/* \n * RESPONSE \n */\n\n";


    public ContextMenuActionListener(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final TemplateService templateService, NewVulnerabilityTab newVulnerabilityTab, IContextMenuInvocation invocation ) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks);
        this.templateService = templateService;
        this.invocation = invocation;
        this.newVulnerabilityTab = newVulnerabilityTab;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        switch (e.getActionCommand()) {
            case "as new vulnerability/notification" -> {
                this.defineCampsNewVulnerabilityTab(invocation.getSelectedMessages()[0]);
                this.selectAppSecFlowTab();
            }
            case "as evidence" -> this.createEvidencesInTempFiles(invocation.getSelectedMessages().length);
            case "as new vulnerability w. evidence" -> {
                this.createEvidencesInTempFiles(invocation.getSelectedMessages().length - 1);
                this.defineCampsNewVulnerabilityTab(invocation.getSelectedMessages()[invocation.getSelectedMessages().length-1]);
                this.selectAppSecFlowTab();
            }
        }
            /*for (IScanIssue issue :
                    this.callbacks.getScanIssues((request.getUrl()+"").replaceAll("\\:[0-9]{1,5}", ""))) {
                System.out.println(issue.getIssueName());
                System.out.println(issue.getIssueType());
                System.out.println(issue.getIssueDetail());


            }*/

    }

    private void defineCampsNewVulnerabilityTab(IHttpRequestResponse requestResponse){
        IRequestInfo request = helpers.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
        IResponseInfo response = helpers.analyzeResponse(requestResponse.getResponse());

        if(!request.toString().isEmpty() && !response.toString().isEmpty()){
            this.newVulnerabilityTab.setRequest(helpers.bytesToString(requestResponse.getRequest()));
            this.newVulnerabilityTab.setResponse(helpers.bytesToString(requestResponse.getResponse()));
            this.newVulnerabilityTab.setTxtFieldProtocol(requestResponse.getHttpService().getProtocol().toUpperCase());
            this.newVulnerabilityTab.setTxtFieldUrl(request.getUrl()+"");
            this.newVulnerabilityTab.setTxtFieldMethod(request.getMethod());
            this.newVulnerabilityTab.setListParameters(request.getParameters());
            this.newVulnerabilityTab.setFromContextMenu(true);

        }
    }

    private void selectAppSecFlowTab(){
        Component current = this.newVulnerabilityTab.$$$getRootComponent$$$().getParent();
        do {
            current = current.getParent();
        } while (!(current instanceof JTabbedPane));

        JTabbedPane tabPane = (JTabbedPane) current;
        for(int i=0; i < tabPane.getTabCount(); i++ ){
            if(tabPane.getTitleAt(i).equals("AppSec Flow")) {
                tabPane.setSelectedIndex(i);
            }
        }
    }

    private void createEvidencesInTempFiles(int maxLenghtFromInvoiceMessages){
        for (int i = 0; i < maxLenghtFromInvoiceMessages; i++) {
            String archiveName = "evidence-part-" + (i + 1) + "-uid-";
            IHttpRequestResponse iHttpRequestResponse = invocation.getSelectedMessages()[i];

            String content = requestHeader +
                    helpers.bytesToString(iHttpRequestResponse.getRequest()) +
                    "\n\n" +
                    responseHeader +
                    helpers.bytesToString(iHttpRequestResponse.getResponse());
            File tempFile = util.createTempFile(archiveName, content);
            if(tempFile != null){
                this.newVulnerabilityTab.addEvidence(new Evidence(tempFile.getAbsolutePath(), tempFile.getName()));
            }
        }
    }

}
