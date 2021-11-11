package view.context_menu.listeners;

import burp.*;
import models.evidences.EvidenceArchive;
import models.tabs_manager.TabsManager;
import utilities.Util;
import view.issues_tab.NewIssueTab;

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


    protected void defineCampsNewIssueTab(NewIssueTab newIssueTab, IHttpRequestResponse requestResponse){
        IRequestInfo request = helpers.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
        IResponseInfo response = helpers.analyzeResponse(requestResponse.getResponse());

        if(!request.toString().isEmpty() && !response.toString().isEmpty()){
            newIssueTab.setRequest(helpers.bytesToString(requestResponse.getRequest()));
            newIssueTab.setResponse(helpers.bytesToString(requestResponse.getResponse()));
            newIssueTab.setTxtFieldProtocol(requestResponse.getHttpService().getProtocol().toUpperCase());
            newIssueTab.setTxtFieldUrl(request.getUrl()+"");
            newIssueTab.setTxtFieldMethod(request.getMethod());
            newIssueTab.setListParameters(request.getParameters());
            newIssueTab.setFromContextMenu(true);
        }
    }

    protected void createEvidencesInTempFiles(NewIssueTab newIssueTab, IContextMenuInvocation invocation){
        for (int i = 0; i < invocation.getSelectedMessages().length; i++) {
            createEvidencesFiles(newIssueTab, invocation, i);
        }
    }

    protected void createEvidencesInTempFiles(NewIssueTab newIssueTab, IContextMenuInvocation invocation, int maxLenghtOfSelectedMessages){
        for (int i = 0; i < maxLenghtOfSelectedMessages; i++) {
            createEvidencesFiles(newIssueTab, invocation, i);
        }
    }

    private void createEvidencesFiles(NewIssueTab newIssueTab, IContextMenuInvocation invocation, int i) {
        String archiveName = "evidence-part-" + (newIssueTab.getQtdEvidence()+1) + "-uid-";
        IHttpRequestResponse iHttpRequestResponse = invocation.getSelectedMessages()[i];

        String content = requestHeader +
                helpers.bytesToString(iHttpRequestResponse.getRequest()) +
                "\n\n" +
                responseHeader +
                helpers.bytesToString(iHttpRequestResponse.getResponse());
        File tempFile = util.createTempFile(archiveName, content);
        if(tempFile != null){
            newIssueTab.addEvidence(new EvidenceArchive(tempFile.getAbsolutePath(), tempFile.getName()));
        }
    }

}
