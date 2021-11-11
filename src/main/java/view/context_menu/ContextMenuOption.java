package view.context_menu;

import burp.*;
import models.tabs_manager.TabsManager;
import utilities.Util;
import view.context_menu.listeners.AsEvidenceContextMenuActionListener;
import view.context_menu.listeners.AsNewIssueContextMenuActionListener;
import view.context_menu.listeners.AsNewIssueWithEvidenceContextMenuActionListener;
import view.context_menu.listeners.ContextMenuActionListener;
import view.issues_tab.NewIssueTab;
import view.issues_tab.closable_pane.ClosablePane;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuOption implements IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final TabsManager tabsManager;
    private Util util;

    public ContextMenuOption(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final TabsManager tabsManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.tabsManager = tabsManager;
        this.util = new Util(this.callbacks, this.helpers);
    }


    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        JMenu itemDefault = new JMenu("Send to AppSecFlow");
        JMenuItem asVulnerability = new JMenuItem("as new issue");
        JMenuItem asVulnerabilityWithEvidence = new JMenuItem("as new issue w. evidence");
        JMenu asEvidence = new JMenu("as evidence");


        JTabbedPane issuesTab = this.tabsManager.getIssuesTab();
        for (int i = 0; i < issuesTab.getTabCount(); i++) {
            System.out.println();
            Component componentAt = issuesTab.getTabComponentAt(i);
            if( componentAt != null){
                JMenuItem jMenuItem = new JMenuItem(((ClosablePane) componentAt).getTabTitle());
                jMenuItem.addActionListener(new AsEvidenceContextMenuActionListener(this.callbacks, this.helpers, this.tabsManager, invocation));
                asEvidence.add(jMenuItem);
            }
        }

        asVulnerability.addActionListener(new AsNewIssueContextMenuActionListener(this.callbacks, this.helpers, this.tabsManager, invocation));
        asVulnerabilityWithEvidence.addActionListener(new AsNewIssueWithEvidenceContextMenuActionListener(this.callbacks, this.helpers, this.tabsManager, invocation));

        itemDefault.add(asVulnerability);
        if(invocation.getSelectedMessages().length >= 2) asVulnerability.setEnabled(false);
        if(invocation.getSelectedMessages().length < 2) asVulnerabilityWithEvidence.setEnabled(false);
        itemDefault.add(asVulnerabilityWithEvidence);
        itemDefault.add(asEvidence);
        items.add(itemDefault);

        return items;
    }

}
