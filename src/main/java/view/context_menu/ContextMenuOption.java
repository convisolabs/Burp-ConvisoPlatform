package view.context_menu;

import burp.*;
import utilities.Util;
import view.context_menu.listeners.ContextMenuActionListener;
import view.issues_tab.NewIssueTab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuOption implements IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final NewIssueTab newIssueTab;
    private Util util;

    public ContextMenuOption(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final NewIssueTab newIssueTab) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.newIssueTab = newIssueTab;
        this.util = new Util(this.callbacks, this.helpers);
    }



    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        JMenu itemDefault = new JMenu("Send to AppSecFlow");
        JMenuItem asVulnerability = new JMenuItem("as new vulnerability/notification");
        JMenuItem asVulnerabilityWithEvidence = new JMenuItem("as new vulnerability w. evidence");
        JMenuItem asEvidence = new JMenuItem("as evidence");

        asVulnerability.addActionListener(new ContextMenuActionListener(this.callbacks, this.helpers, this.newIssueTab, invocation));
        asVulnerabilityWithEvidence.addActionListener(new ContextMenuActionListener(this.callbacks, this.helpers, this.newIssueTab, invocation));
        asEvidence.addActionListener(new ContextMenuActionListener(this.callbacks, this.helpers, this.newIssueTab, invocation));

        itemDefault.add(asVulnerability);
        if(invocation.getSelectedMessages().length >= 2) asVulnerability.setEnabled(false);
        if(invocation.getSelectedMessages().length < 2) asVulnerabilityWithEvidence.setEnabled(false);
        itemDefault.add(asVulnerabilityWithEvidence);
        itemDefault.add(asEvidence);
        items.add(itemDefault);

        return items;
    }

}
