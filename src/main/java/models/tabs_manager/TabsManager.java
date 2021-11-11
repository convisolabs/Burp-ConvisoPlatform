package models.tabs_manager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import models.services_manager.ServicesManager;
import utilities.Util;
import view.settings.config.ConfigurationTab;
import view.issues_tab.closable_pane.ClosablePane;
import view.management.allocated_project.AllocatedProjectsTab;
import view.management.playbooks.PlaybookTab;
import view.issues_tab.NewIssueTab;


import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class TabsManager implements ITab {

    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;
    protected ServicesManager servicesManager;
    protected Util util;

    private final String FLOW_API_KEY = "FLOW.API.KEY";
    private final int ISSUES_INDEX = 0;
    private final int MANAGETMENT_INDEX = 1;
    private final int CONFIG_INDEX = 2;

    private final int[] ALLOCATED_PROJECT_TAB = {1, 1};

    /* Tabs */
    private ConfigurationTab configurationTab;
    ArrayList<NewIssueTab> issuesArray = new ArrayList<>();
    private AllocatedProjectsTab allocatedProjectsTab;
    private PlaybookTab playbookTab;


    /* JTabbeds */
    private JTabbedPane rootTab;
    private JTabbedPane issuesTab;
    private JTabbedPane managementTab;
    private JTabbedPane settingsTab;


    public TabsManager(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
        this.servicesManager = servicesManager;
        this.issuesTab = new JTabbedPane();//new JideTabbedPane();
        this.managementTab = new JTabbedPane();
        this.settingsTab = new JTabbedPane();
        this.rootTab = new JTabbedPane();
    }

    public void initializeComponents() {
        /* Initialization of components tabs */
        initializeIssuesTab();
        initializeManagementTab();
        initializeConfigTab();


        this.rootTab.add("Issues", this.issuesTab);
        this.rootTab.add("Management", this.managementTab);
        this.rootTab.add("Settings", this.settingsTab);
    }


    private void initializeIssuesTab() {
        /* Occurrences tab */
        NewIssueTab newIssueTab = new NewIssueTab(this.callbacks, this.helpers, this.servicesManager, this);
        newIssueTab.initializeComponent();
        this.issuesArray.add(newIssueTab);
        this.issuesTab.addTab(null, newIssueTab.$$$getRootComponent$$$());//
        this.issuesTab.addTab("+", new JPanel());
        this.issuesTab.setTabComponentAt(0, new ClosablePane("#1"));

        SwingUtilities.invokeLater(() -> {
            this.issuesTab.addChangeListener(e -> {
                int selectedIndex = issuesTab.getSelectedIndex();
                if (issuesTab.getTitleAt(selectedIndex).equals("+")) {
                    NewIssueTab issue = new NewIssueTab(this.callbacks, this.helpers, this.servicesManager, this);
                    issue.initializeComponent();
                    this.issuesArray.add(issue);
                    this.issuesTab.setSelectedIndex(0);
                    this.issuesTab.insertTab(null, null, issue.$$$getRootComponent$$$(), null, selectedIndex);
                    this.issuesTab.setTabComponentAt(selectedIndex, new ClosablePane("#" + issuesArray.size()));
                    this.issuesTab.setSelectedIndex(selectedIndex);
                }
            });
        });
    }

    private void initializeManagementTab() {
        /* Management tab */
        this.allocatedProjectsTab = new AllocatedProjectsTab(this.callbacks, this.helpers, this.servicesManager, this);
        this.playbookTab = new PlaybookTab(this.callbacks, this.helpers, this.servicesManager);

        this.allocatedProjectsTab.initializeComponent();
        this.playbookTab.initializeComponent();

        this.managementTab.addTab("Playbooks", this.playbookTab.$$$getRootComponent$$$());
        this.managementTab.addTab("Allocated Projects", this.allocatedProjectsTab.$$$getRootComponent$$$());

    }

    private void initializeConfigTab() {
        /* Configuration tab */
        this.configurationTab = new ConfigurationTab(this.callbacks, this.helpers, this.servicesManager);

        this.configurationTab.initializeComponent();

        this.settingsTab.addTab("Configuration", this.configurationTab.$$$getRootComponent$$$());


    }

    public void verifyIfApiKeyIsSet() {
        if (callbacks.loadExtensionSetting(FLOW_API_KEY) == null || callbacks.loadExtensionSetting(FLOW_API_KEY).isEmpty()) {
            this.rootTab.setSelectedIndex(CONFIG_INDEX);
        }
    }

    public void setFocusToAllocatedProjectsTab() {
        this.rootTab.setSelectedIndex(ALLOCATED_PROJECT_TAB[0]);
        this.managementTab.setSelectedIndex(ALLOCATED_PROJECT_TAB[1]);
    }

    public void setFocusToLastIssue(){
        this.setFocusToAppSecFlow();
        this.rootTab.setSelectedIndex(ISSUES_INDEX);
        this.issuesTab.setSelectedIndex(this.issuesTab.getTabCount()-1);
    }

    private void setFocusToAppSecFlow() {
        JTabbedPane tabPane = (JTabbedPane) this.rootTab.getParent();
        for (int i = 0; i < tabPane.getTabCount(); i++) {
            if (tabPane.getTitleAt(i).equals("AppSec Flow")) {
                tabPane.setSelectedIndex(i);
            }
        }
    }

    public NewIssueTab returnLastIssue(){
        return this.getIssuesArray().get(this.getIssuesArray().size()-1);
    }

    public JTabbedPane getRootTab() {
        return rootTab;
    }

    public ConfigurationTab getConfigurationTab() {
        return configurationTab;
    }

    public AllocatedProjectsTab getAllocatedProjectsTab() {
        return allocatedProjectsTab;
    }

    public PlaybookTab getPlaybookTab() {
        return playbookTab;
    }

    public ArrayList<NewIssueTab> getIssuesArray() {
        return issuesArray;
    }

    public JTabbedPane getIssuesTab() {
        return issuesTab;
    }

    /* IMPLEMENTAÇÃO DO ITAB */
    @Override
    public String getTabCaption() {
        return "AppSec Flow";
    }

    @Override
    public Component getUiComponent() {
        return rootTab;
    }
}
