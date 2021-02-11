package burp;

import services.TemplateService;
import view.config.ConfigurationTab;
import view.context_menu.ContextMenuOption;
import view.new_vulnerability.NewVulnerabilityTab;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public class BurpExtender implements IBurpExtender, ITab {



    private JTabbedPane tabsHandler;

    private ConfigurationTab configurationTab;
    private NewVulnerabilityTab newVulnerabilityTab;
    private JTabbedPane teste;
    //private VulnersService vulnersService;
    //private Map<String, Domain> domains = new HashMap<>();
    private Map<String, Map<String, String>> matchRules = new HashMap<>();

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ContextMenuOption contextMenuOption;
    private TemplateService templateService;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.templateService = new TemplateService(this.callbacks, this.helpers);
        this.configurationTab = new ConfigurationTab(this.callbacks, this.helpers);
        this.newVulnerabilityTab = new NewVulnerabilityTab(this.callbacks, this.helpers, this.templateService);

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
            callbacks.addSuiteTab(BurpExtender.this);
        });



        /*
         * Cria a opção no menu do botão direito, tambem conhecido como contextmenu
         */

        this.contextMenuOption = new ContextMenuOption(this.callbacks, this.helpers, this.newVulnerabilityTab, this.templateService);
        this.callbacks.registerContextMenuFactory(this.contextMenuOption);


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
