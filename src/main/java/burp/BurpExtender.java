package burp;

import models.services_manager.ServicesManager;
import models.tabs_manager.TabsManager;
import utilities.Util;
import view.context_menu.ContextMenuOption;

import javax.swing.*;

public class BurpExtender implements IBurpExtender {



    private TabsManager tabsManager;

    private ServicesManager servicesManager;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ContextMenuOption contextMenuOption;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.servicesManager = new ServicesManager(this.callbacks, this.helpers);

        callbacks.setExtensionName("Conviso Platform");


        tabsManager = new TabsManager(this.callbacks, this.helpers, this.servicesManager);

        SwingUtilities.invokeLater(() -> {

            tabsManager.initializeComponents();

            callbacks.addSuiteTab(tabsManager);

            tabsManager.verifyIfApiKeyIsSet();

        });


        /*
         * Creates the submenu in the right click, also known as context menu.
         */

        this.contextMenuOption = new ContextMenuOption(this.callbacks, this.helpers, tabsManager);
        this.callbacks.registerContextMenuFactory(this.contextMenuOption);


        new Util(this.callbacks).sendStdout("Extension loaded");
    }




}
