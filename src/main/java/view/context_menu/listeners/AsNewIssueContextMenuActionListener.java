package view.context_menu.listeners;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import models.tabs_manager.TabsManager;
import view.issues_tab.NewIssueTab;

import java.awt.event.ActionEvent;

public class AsNewIssueContextMenuActionListener extends CustomContextMenuActionListener{

    public AsNewIssueContextMenuActionListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, TabsManager tabsManager, IContextMenuInvocation invocation) {
        super(callbacks, helpers, tabsManager, invocation);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        tabsManager.setFocusToLastIssue();
        this.defineCampsNewIssueTab(tabsManager.returnLastIssue(), invocation.getSelectedMessages()[0]);
    }
}
