package view.context_menu.listeners;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import models.tabs_manager.TabsManager;

import java.awt.event.ActionEvent;

public class AsNewIssueWithEvidenceContextMenuActionListener extends CustomContextMenuActionListener{

    public AsNewIssueWithEvidenceContextMenuActionListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, TabsManager tabsManager, IContextMenuInvocation invocation) {
        super(callbacks, helpers, tabsManager, invocation);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        tabsManager.setFocusToLastIssue();
        this.createEvidencesInTempFiles(tabsManager.returnLastIssue(), invocation, invocation.getSelectedMessages().length-1);
        this.defineCampsNewIssueTab(tabsManager.returnLastIssue(), invocation.getSelectedMessages()[invocation.getSelectedMessages().length - 1]);
    }
}
