package view.context_menu;

import burp.*;
import services.TemplateService;
import utilities.Util;
import view.context_menu.listeners.ContextMenuActionListener;
import view.new_vulnerability.NewVulnerabilityTab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuOption implements IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private TemplateService templateService;
    private final NewVulnerabilityTab newVulnerabilityTab;
    private Util util;

    public ContextMenuOption(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final NewVulnerabilityTab newVulnerabilityTab, final TemplateService templateService) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.newVulnerabilityTab = newVulnerabilityTab;
        this.util = new Util(this.callbacks, this.helpers);
        this.templateService = templateService;
    }



    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<JMenuItem>();
        JMenuItem itemDefault = new JMenuItem("Send to AppSecFlow");

        itemDefault.addActionListener(new ContextMenuActionListener(this.callbacks, this.helpers, this.templateService, this.newVulnerabilityTab, invocation));
        items.add(itemDefault);

        return items;
    }

}
