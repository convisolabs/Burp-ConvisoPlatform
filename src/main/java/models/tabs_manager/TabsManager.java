package models.tabs_manager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import models.services_manager.ServicesManager;
import utilities.Util;
import view.settings.config.ConfigurationTab;
import view.vulnerabilities_tab.closable_pane.ClosablePane;
import view.requirements.requirements.RequirementsTab;
import view.vulnerabilities_tab.NewVulnerabilityTab;


import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class TabsManager implements ITab {

    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;
    protected ServicesManager servicesManager;
    protected Util util;

    private final String CONVISO_API_KEY = "CONVISO.API.KEY";
    private final int VULNERABILITIES_INDEX = 0;
    private final int REQUIREMENTS_INDEX = 1;
    private final int CONFIG_INDEX = 2;

    private ConfigurationTab configurationTab;
    ArrayList<NewVulnerabilityTab> vulnerabilities = new ArrayList<>();
    private RequirementsTab requirementsTab;


    private JTabbedPane rootTab;
    private JTabbedPane vulnerabilitiesTab;
    private JTabbedPane requirementsTabPane;
    private JTabbedPane settingsTab;


    public TabsManager(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
        this.servicesManager = servicesManager;
        this.vulnerabilitiesTab = new JTabbedPane();
        this.requirementsTabPane = new JTabbedPane();
        this.settingsTab = new JTabbedPane();
        this.rootTab = new JTabbedPane();
    }

    public void initializeComponents() {
        initializeVulnerabilitiesTab();
        initializeRequirementsTab();
        initializeConfigTab();


        this.rootTab.add("Vulnerabilities", this.vulnerabilitiesTab);
        this.rootTab.add("Requirements", this.requirementsTabPane);
        this.rootTab.add("Settings", this.settingsTab);

        this.rootTab.addChangeListener(e -> {
            if (this.rootTab.getSelectedIndex() == REQUIREMENTS_INDEX && this.requirementsTab != null) {
                SwingUtilities.invokeLater(() -> this.requirementsTab.refreshRequirementsAsync());
            }
        });
    }


    private void initializeVulnerabilitiesTab() {
        NewVulnerabilityTab newVulnerabilityTab = new NewVulnerabilityTab(this.callbacks, this.helpers, this.servicesManager, this);
        newVulnerabilityTab.initializeComponent();
        this.vulnerabilities.add(newVulnerabilityTab);
        this.vulnerabilitiesTab.addTab(null, newVulnerabilityTab.$$$getRootComponent$$$());
        this.vulnerabilitiesTab.addTab("+", new JPanel());
        this.vulnerabilitiesTab.setTabComponentAt(0, new ClosablePane("#1"));

        SwingUtilities.invokeLater(() -> {
            this.vulnerabilitiesTab.addChangeListener(e -> {
                int selectedIndex = vulnerabilitiesTab.getSelectedIndex();
                if (vulnerabilitiesTab.getTitleAt(selectedIndex).equals("+")) {
                    NewVulnerabilityTab vulnerabilityTab = new NewVulnerabilityTab(this.callbacks, this.helpers, this.servicesManager, this);
                    vulnerabilityTab.initializeComponent();
                    this.vulnerabilities.add(vulnerabilityTab);
                    this.vulnerabilitiesTab.setSelectedIndex(0);
                    this.vulnerabilitiesTab.insertTab(null, null, vulnerabilityTab.$$$getRootComponent$$$(), null, selectedIndex);
                    this.vulnerabilitiesTab.setTabComponentAt(selectedIndex, new ClosablePane("#" + vulnerabilities.size()));
                    this.vulnerabilitiesTab.setSelectedIndex(selectedIndex);
                }
            });
        });
    }

    private void initializeRequirementsTab() {
        this.requirementsTab = new RequirementsTab(this.callbacks, this.helpers, this.servicesManager);

        this.requirementsTab.initializeComponent();

        this.requirementsTabPane.addTab("Requirements", this.requirementsTab.$$$getRootComponent$$$());
    }

    private void initializeConfigTab() {
        this.configurationTab = new ConfigurationTab(this.callbacks, this.helpers, this.servicesManager);

        this.configurationTab.initializeComponent();

        this.settingsTab.addTab("Configuration", this.configurationTab.$$$getRootComponent$$$());


    }

    public void verifyIfApiKeyIsSet() {
        if (callbacks.loadExtensionSetting(CONVISO_API_KEY) == null || callbacks.loadExtensionSetting(CONVISO_API_KEY).isEmpty()) {
            this.rootTab.setSelectedIndex(CONFIG_INDEX);
        }
    }

    public void setFocusToLastVulnerability(){
        this.setFocusToConvisoPlatformTab();
        this.rootTab.setSelectedIndex(VULNERABILITIES_INDEX);
        this.vulnerabilitiesTab.setSelectedIndex(this.vulnerabilitiesTab.getTabCount()-1);
    }

    private void setFocusToConvisoPlatformTab() {
        JTabbedPane tabPane = (JTabbedPane) this.rootTab.getParent();
        for (int i = 0; i < tabPane.getTabCount(); i++) {
            if (tabPane.getTitleAt(i).equals("Conviso Platform")) {
                tabPane.setSelectedIndex(i);
            }
        }
    }

    public NewVulnerabilityTab returnLastVulnerability(){
        return this.getVulnerabilities().get(this.getVulnerabilities().size()-1);
    }

    public JTabbedPane getRootTab() {
        return rootTab;
    }

    public ConfigurationTab getConfigurationTab() {
        return configurationTab;
    }

    public RequirementsTab getRequirementsTab() {
        return requirementsTab;
    }

    public ArrayList<NewVulnerabilityTab> getVulnerabilities() {
        return vulnerabilities;
    }

    public JTabbedPane getVulnerabilitiesTab() {
        return vulnerabilitiesTab;
    }

    @Override
    public String getTabCaption() {
        return "Conviso Platform";
    }

    @Override
    public Component getUiComponent() {
        return rootTab;
    }
}
