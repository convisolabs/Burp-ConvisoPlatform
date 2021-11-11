package view.context_menu.listeners;

import burp.*;
import models.tabs_manager.TabsManager;
import view.issues_tab.NewIssueTab;
import java.awt.event.ActionEvent;


public class AsEvidenceContextMenuActionListener extends CustomContextMenuActionListener {

    public AsEvidenceContextMenuActionListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, TabsManager tabsManager, IContextMenuInvocation invocation) {
        super(callbacks, helpers, tabsManager, invocation);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        int indexOfClickedTab = Integer.parseInt(e.getActionCommand().replace("#", "")) - 1;
        NewIssueTab newIssueTab = this.tabsManager.getIssuesArray().get(indexOfClickedTab);

        this.createEvidencesInTempFiles(newIssueTab, this.invocation);
    }



}
