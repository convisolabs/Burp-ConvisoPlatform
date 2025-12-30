package view.context_menu.listeners;

import burp.*;
import models.attachments.AttachmentArchive;
import models.tabs_manager.TabsManager;
import utilities.Util;
import view.vulnerabilities_tab.NewVulnerabilityTab;

import java.awt.event.ActionListener;
import java.io.File;

public abstract class CustomContextMenuActionListener implements ActionListener {

    String requestHeader = "/* \n * REQUEST \n */\n\n";
    String responseHeader = "/* \n * RESPONSE \n */\n\n";
    protected final IBurpExtenderCallbacks callbacks;
    protected final IExtensionHelpers helpers;
    protected final TabsManager tabsManager;
    protected IContextMenuInvocation invocation;
    protected final Util util;

    public CustomContextMenuActionListener(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final TabsManager tabsManager, IContextMenuInvocation invocation ) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.tabsManager = tabsManager;
        this.invocation = invocation;
        this.util = new Util(callbacks, helpers);
    }


    protected void defineCampsNewVulnerabilityTab(NewVulnerabilityTab newVulnerabilityTab, IHttpRequestResponse requestResponse){
        IRequestInfo request = helpers.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
        IResponseInfo response = helpers.analyzeResponse(requestResponse.getResponse());

        if(!request.toString().isEmpty() && !response.toString().isEmpty()){
            newVulnerabilityTab.setRequest(helpers.bytesToString(requestResponse.getRequest()));
            newVulnerabilityTab.setResponse(helpers.bytesToString(requestResponse.getResponse()));
            newVulnerabilityTab.setTxtFieldProtocol(requestResponse.getHttpService().getProtocol().toUpperCase());
            newVulnerabilityTab.setTxtFieldUrl(request.getUrl()+"");
            newVulnerabilityTab.setTxtFieldMethod(request.getMethod());
            newVulnerabilityTab.setListParameters(request.getParameters());
            newVulnerabilityTab.setFromContextMenu(true);
        }
    }

    protected void createAttachmentsInTempFiles(NewVulnerabilityTab newVulnerabilityTab, IContextMenuInvocation invocation){
        for (int i = 0; i < invocation.getSelectedMessages().length; i++) {
            createAttachmentsFiles(newVulnerabilityTab, invocation, i);
        }
    }

    protected void createAttachmentsInTempFiles(NewVulnerabilityTab newVulnerabilityTab, IContextMenuInvocation invocation, int maxLenghtOfSelectedMessages){
        for (int i = 0; i < maxLenghtOfSelectedMessages; i++) {
            createAttachmentsFiles(newVulnerabilityTab, invocation, i);
        }
    }

    private void createAttachmentsFiles(NewVulnerabilityTab newVulnerabilityTab, IContextMenuInvocation invocation, int i) {
        String archiveName = "attachment-part-" + (newVulnerabilityTab.getQtdEvidence()+1) + "-uid-";
        IHttpRequestResponse iHttpRequestResponse = invocation.getSelectedMessages()[i];

        String content = requestHeader +
                helpers.bytesToString(iHttpRequestResponse.getRequest()) +
                "\n\n" +
                responseHeader +
                helpers.bytesToString(iHttpRequestResponse.getResponse());
        File tempFile = util.createTempFile(archiveName, content);
        if(tempFile != null){
            newVulnerabilityTab.addEvidence(new AttachmentArchive(tempFile.getAbsolutePath(), tempFile.getName()));
        }
    }

}
