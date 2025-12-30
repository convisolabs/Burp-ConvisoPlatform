package view.context_menu;

import burp.*;
import models.tabs_manager.TabsManager;
import utilities.Util;
import view.context_menu.listeners.AsAttachmentContextMenuActionListener;
import view.context_menu.listeners.AsNewVulnerabilityContextMenuActionListener;
import view.context_menu.listeners.AsNewVulnerabilityWithAttachmentContextMenuActionListener;
import view.context_menu.listeners.ContextMenuActionListener;
import view.vulnerabilities_tab.closable_pane.ClosablePane;

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
        JMenu itemDefault = new JMenu("Send to Conviso Platform");
        JMenuItem asVulnerability = new JMenuItem("as new vulnerability");
        JMenuItem asVulnerabilityWithAttachment = new JMenuItem("as new vulnerability w. attachment");
        JMenu asAttachment = new JMenu("as attachment");


        JTabbedPane vulnerabilitiesTab = this.tabsManager.getVulnerabilitiesTab();
        for (int i = 0; i < vulnerabilitiesTab.getTabCount(); i++) {
            System.out.println();
            Component componentAt = vulnerabilitiesTab.getTabComponentAt(i);
            if( componentAt != null){
                JMenuItem jMenuItem = new JMenuItem(((ClosablePane) componentAt).getTabTitle());
                jMenuItem.addActionListener(new AsAttachmentContextMenuActionListener(this.callbacks, this.helpers, this.tabsManager, invocation));
                asAttachment.add(jMenuItem);
            }
        }

        asVulnerability.addActionListener(new AsNewVulnerabilityContextMenuActionListener(this.callbacks, this.helpers, this.tabsManager, invocation));
        asVulnerabilityWithAttachment.addActionListener(new AsNewVulnerabilityWithAttachmentContextMenuActionListener(this.callbacks, this.helpers, this.tabsManager, invocation));

        itemDefault.add(asVulnerability);
        if(invocation.getSelectedMessages().length >= 2) asVulnerability.setEnabled(false);
        if(invocation.getSelectedMessages().length < 2) asVulnerabilityWithAttachment.setEnabled(false);
        itemDefault.add(asVulnerabilityWithAttachment);
        itemDefault.add(asAttachment);
        items.add(itemDefault);

        return items;
    }

}
