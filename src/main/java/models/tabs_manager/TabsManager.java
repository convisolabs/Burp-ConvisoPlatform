package models.tabs_manager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import models.services_manager.ServicesManager;
import services.IssuesService;
import utilities.Util;
import view.settings.config.ConfigurationTab;
import view.issues_tab.closable_pane.ClosablePane;
import view.management.allocated_analysis.AllocatedAnalysesTab;
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
    private final int MANAGEMENT_INDEX = 1;
    private final int CONFIG_INDEX = 2;

    private final int[] ALLOCATED_ANALYSIS_TAB = {1, 1};

    /* Tabs */
    private ConfigurationTab configurationTab;
    ArrayList<NewIssueTab> issuesArray = new ArrayList<>();
    private AllocatedAnalysesTab allocatedAnalysesTab;
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
        /* Issues tab */
        IssuesService issuesService = this.servicesManager.getIssueService();
        issuesService.loadWorkingIssuesLocally();

        if(issuesService.getSavedIssues().size() > 0){

            int load = JOptionPane.showConfirmDialog(this.getRootTab(), "Do you wish to load saved issues?", "Load working issues", JOptionPane.YES_NO_OPTION);
            System.out.println(load);
            if(load == JOptionPane.YES_OPTION){
                for (String jsonObject :
                        issuesService.getSavedIssues()) {
                    NewIssueTab issue = new NewIssueTab(this.callbacks, this.helpers, this.servicesManager, this);
                    issue.initializeComponent();
                    issue.fromJsonObject(jsonObject);
                    this.issuesArray.add(issue);
                    this.issuesTab.insertTab(null, null, issue.$$$getRootComponent$$$(), null, issuesArray.size()-1);
                    this.issuesTab.setTabComponentAt(issuesArray.size()-1, new ClosablePane("#" + issuesArray.size()));
                }
            }else{
                NewIssueTab newIssueTab = new NewIssueTab(this.callbacks, this.helpers, this.servicesManager, this);
                newIssueTab.initializeComponent();
                this.issuesArray.add(newIssueTab);
                this.issuesTab.addTab(null, newIssueTab.$$$getRootComponent$$$());//
                this.issuesTab.setTabComponentAt(0, new ClosablePane("#1"));
            }
            issuesService.clearWorkingIssues();
            this.issuesTab.setSelectedIndex(0);
        }else{
            NewIssueTab newIssueTab = new NewIssueTab(this.callbacks, this.helpers, this.servicesManager, this);
            newIssueTab.initializeComponent();
            this.issuesArray.add(newIssueTab);
            this.issuesTab.addTab(null, newIssueTab.$$$getRootComponent$$$());//
            this.issuesTab.setTabComponentAt(0, new ClosablePane("#1"));
        }
        this.issuesTab.addTab("+", new JPanel());


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
        this.allocatedAnalysesTab = new AllocatedAnalysesTab(this.callbacks, this.helpers, this.servicesManager, this);
        this.playbookTab = new PlaybookTab(this.callbacks, this.helpers, this.servicesManager);

        this.allocatedAnalysesTab.initializeComponent();
        this.playbookTab.initializeComponent();

        this.managementTab.addTab("Playbooks", this.playbookTab.$$$getRootComponent$$$());
        this.managementTab.addTab("Allocated Projects", this.allocatedAnalysesTab.$$$getRootComponent$$$());

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
        this.rootTab.setSelectedIndex(ALLOCATED_ANALYSIS_TAB[0]);
        this.managementTab.setSelectedIndex(ALLOCATED_ANALYSIS_TAB[1]);
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

    public void saveIssue(String objectToSave){
        IssuesService issuesService = this.servicesManager.getIssueService();
        if(!issuesService.verifySavedIssue(objectToSave)) {
            issuesService.addToWorkingIssues(objectToSave);
            issuesService.saveWorkingIssuesLocally();
        }
    }

    public void removeIssue(String objectToRemove){
        IssuesService issuesService = this.servicesManager.getIssueService();
        if(issuesService.verifySavedIssue(objectToRemove)){
            issuesService.removeFromWorkingIssues(objectToRemove);
        }
        issuesService.saveWorkingIssuesLocally();
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

    public AllocatedAnalysesTab getAllocatedProjectsTab() {
        return allocatedAnalysesTab;
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
