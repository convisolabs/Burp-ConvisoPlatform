package view.context_menu.listeners;

import burp.*;
import models.tabs_manager.TabsManager;
import view.vulnerabilities_tab.NewVulnerabilityTab;
import java.awt.event.ActionEvent;


public class AsAttachmentContextMenuActionListener extends CustomContextMenuActionListener {

    public AsAttachmentContextMenuActionListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, TabsManager tabsManager, IContextMenuInvocation invocation) {
        super(callbacks, helpers, tabsManager, invocation);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        int indexOfClickedTab = Integer.parseInt(e.getActionCommand().replace("#", "")) - 1;
        NewVulnerabilityTab newVulnerabilityTab = this.tabsManager.getVulnerabilities().get(indexOfClickedTab);

        this.createAttachmentsInTempFiles(newVulnerabilityTab, this.invocation);
    }



}
