package burp;

import utilities.Util;
import view.config.ConfigurationTab;
import view.context_menu.ContextMenuOption;
import view.management.allocated_projects.AllocatedProjectsTab;
import view.management.playbooks.PlaybookTab;
import view.new_vulnerability.NewVulnerabilityTab;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {



    private JTabbedPane tabsHandler;

    private ConfigurationTab configurationTab;
    private NewVulnerabilityTab newVulnerabilityTab;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ContextMenuOption contextMenuOption;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.configurationTab = new ConfigurationTab(this.callbacks, this.helpers);
        this.newVulnerabilityTab = new NewVulnerabilityTab(this.callbacks, this.helpers);
        AllocatedProjectsTab allocatedProjectsTab = new AllocatedProjectsTab(this.callbacks, this.helpers);

        allocatedProjectsTab.initializeComponent();

        PlaybookTab playbookTab = new PlaybookTab(this.callbacks, this.helpers);

        playbookTab.initializeComponent();

        /*
        * Cria a aba no BURP
        */
        callbacks.setExtensionName("AppSec Flow");
        tabsHandler = new JTabbedPane();
        SwingUtilities.invokeLater(() -> {


            this.newVulnerabilityTab.initializeComponent();
            tabsHandler.addTab("New Vulnerability", newVulnerabilityTab.$$$getRootComponent$$$());
            this.configurationTab.initializeComponent();
            tabsHandler.addTab("Configuration", configurationTab.$$$getRootComponent$$$());
            tabsHandler.addTab("Allocated Projects", allocatedProjectsTab.$$$getRootComponent$$$());
            tabsHandler.addTab("Playbooks", playbookTab.$$$getRootComponent$$$());
            callbacks.addSuiteTab(BurpExtender.this);

            final String FLOW_API_KEY = "FLOW.API.KEY";
            if(callbacks.loadExtensionSetting(FLOW_API_KEY) == null || callbacks.loadExtensionSetting(FLOW_API_KEY).isEmpty()){
                this.tabsHandler.setSelectedIndex(1);
            }
        });


        /*
         * Cria a opção no menu do botão direito, tambem conhecido como contextmenu
         */

        this.contextMenuOption = new ContextMenuOption(this.callbacks, this.helpers, this.newVulnerabilityTab);
        this.callbacks.registerContextMenuFactory(this.contextMenuOption);


        new Util(this.callbacks).sendStdout("Extension loaded");
    }

    /* IMPLEMENTAÇÃO DO ITAB */
    @Override
    public String getTabCaption() {
        return "AppSec Flow";
    }

    @Override
    public Component getUiComponent() {
        return tabsHandler;
    }


}
