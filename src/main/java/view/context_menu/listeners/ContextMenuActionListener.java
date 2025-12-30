package view.context_menu.listeners;

import burp.*;
import models.tabs_manager.TabsManager;
import utilities.Util;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class ContextMenuActionListener implements ActionListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IContextMenuInvocation invocation;
    private Util util;
    private final TabsManager tabsManager;


    public ContextMenuActionListener(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final TabsManager tabsManager, IContextMenuInvocation invocation) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks);
        this.invocation = invocation;
        this.tabsManager = tabsManager;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
    }

}
