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

        callbacks.setExtensionName("AppSec Flow");


        tabsManager = new TabsManager(this.callbacks, this.helpers, this.servicesManager);

        SwingUtilities.invokeLater(() -> {

            tabsManager.initializeComponents();

//            this.newVulnerabilityTab.initializeComponent();
//            tabsManager.addTab("New Vulnerability", newVulnerabilityTab.$$$getRootComponent$$$());
//            this.configurationTab.initializeComponent();
//            tabsManager.addTab("Configuration", configurationTab.$$$getRootComponent$$$());
//            tabsManager.addTab("Allocated Projects", allocatedProjectsTab.$$$getRootComponent$$$());
//            tabsManager.addTab("Playbooks", playbookTab.$$$getRootComponent$$$());
            callbacks.addSuiteTab(tabsManager);

            tabsManager.verifyApiKey();
        });


        /*
         * Cria a opção no menu do botão direito, tambem conhecido como contextmenu
         */

        this.contextMenuOption = new ContextMenuOption(this.callbacks, this.helpers, tabsManager.getNewVulnerabilityTab());
        this.callbacks.registerContextMenuFactory(this.contextMenuOption);


        new Util(this.callbacks).sendStdout("Extension loaded");
    }




}
