package view.context_menu.listeners;

import burp.*;
import services.TemplateService;
import utilities.Util;
import view.new_vulnerability.NewVulnerabilityTab;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ContextMenuActionListener implements ActionListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private TemplateService templateService;
    private IContextMenuInvocation invocation;
    private final NewVulnerabilityTab newVulnerabilityTab;

    public ContextMenuActionListener(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final TemplateService templateService, NewVulnerabilityTab newVulnerabilityTab, IContextMenuInvocation invocation ) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.templateService = templateService;
        this.invocation = invocation;
        this.newVulnerabilityTab = newVulnerabilityTab;
    }


    @Override
    public void actionPerformed(ActionEvent e) {
        IHttpRequestResponse requestResponse = invocation.getSelectedMessages()[0];

        IRequestInfo request = helpers.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());

        if(!request.toString().isEmpty() && !request.toString().isEmpty()){
            newVulnerabilityTab.setRequest(helpers.bytesToString(requestResponse.getRequest()));
            newVulnerabilityTab.setResponse(helpers.bytesToString(requestResponse.getResponse()));
            newVulnerabilityTab.setTxtFieldProtocol(requestResponse.getHttpService().getProtocol().toUpperCase());
            newVulnerabilityTab.setTxtFieldUrl(request.getUrl()+"");
            newVulnerabilityTab.setTxtFieldMethod(request.getMethod());
            newVulnerabilityTab.setListParameters(this.getParametersList(request));
            newVulnerabilityTab.setFromContextMenu(true);


            /*for (IScanIssue issue :
                    this.callbacks.getScanIssues((request.getUrl()+"").replaceAll("\\:[0-9]{1,5}", ""))) {
                System.out.println(issue.getIssueName());
                System.out.println(issue.getIssueType());
                System.out.println(issue.getIssueDetail());


            }*/
        }
    }

    private String[] getParametersList(IRequestInfo request){
        String[] params = new String[request.getParameters().size()];
        for (int i = 0; i < request.getParameters().size(); i++) {
            params[i] = request.getParameters().get(i).getName()+"="+request.getParameters().get(i).getValue();
        }
        return params;
    }
}
