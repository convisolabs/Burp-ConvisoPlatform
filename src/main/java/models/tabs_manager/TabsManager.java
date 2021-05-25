package models.tabs_manager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import com.jidesoft.swing.JideTabbedPane;
import models.services_manager.ServicesManager;
import org.jdesktop.swingx.JXCollapsiblePane;
import utilities.Util;
import view.config.ConfigurationTab;
import view.management.allocated_projects.AllocatedProjectsTab;
import view.management.playbooks.PlaybookTab;
import view.new_vulnerability.NewIssueTab;

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

    /* Tabs */
    private ConfigurationTab configurationTab;
    ArrayList<NewIssueTab> issuesArray = new ArrayList<>();
    private NewIssueTab newIssueTab;
    private AllocatedProjectsTab allocatedProjectsTab;
    private PlaybookTab playbookTab;


    /* JTabbeds */
    private JTabbedPane rootTab;
    private JTabbedPane occurencesTab;
    private JTabbedPane managementTab;
    private JTabbedPane configTab;


    public TabsManager(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
        this.servicesManager = servicesManager;
        this.occurencesTab = new JTabbedPane();//new JideTabbedPane();
        this.managementTab = new JTabbedPane();
        this.configTab = new JTabbedPane();
        this.rootTab = new JTabbedPane();
    }

    public void initializeComponents(){

        /* Initialization of components tabs */
        initializeIssuesTab();
        initializeManagementTab();
        initializeConfigTab();





        this.occurencesTab.addTab("New issue #"+issuesArray.size(), newIssueTab.$$$getRootComponent$$$());
        this.occurencesTab.addTab("+", new JPanel());
        //add the Listener
        this.occurencesTab.addChangeListener(e -> {
            int selectedIndex = occurencesTab.getSelectedIndex();
            if(occurencesTab.getTitleAt(selectedIndex).equals("+")){
                System.out.println(true);
                NewIssueTab issue = new NewIssueTab(this.callbacks, this.helpers, this.servicesManager);
                this.issuesArray.add(issue);

                this.occurencesTab.setSelectedIndex(0);
                this.occurencesTab.insertTab("New issue #"+issuesArray.size(),null, issue.$$$getRootComponent$$$(), null, selectedIndex);
                this.occurencesTab.setSelectedIndex(selectedIndex);

//
            }
//            this.util.clearTerminal();
        });


        idk();


    }

    private void idk(){
        this.rootTab.add("Issues",this.occurencesTab);
        this.rootTab.add("Management", this.managementTab);
        this.rootTab.add("Configuration", this.configTab);
    }

    private void initializeIssuesTab(){
        /* Occurrences tab */
        this.newIssueTab = new NewIssueTab(this.callbacks, this.helpers, this.servicesManager);
        this.newIssueTab.initializeComponent();
        this.issuesArray.add(this.newIssueTab);
    }

    private void initializeManagementTab(){
        /* Management tab */
        this.allocatedProjectsTab = new AllocatedProjectsTab(this.callbacks, this.helpers, this.servicesManager);
        this.playbookTab = new PlaybookTab(this.callbacks, this.helpers, this.servicesManager);

        this.allocatedProjectsTab.initializeComponent();
        this.playbookTab.initializeComponent();
    }

    private void initializeConfigTab(){
        /* Configuration tab */
        this.configurationTab = new ConfigurationTab(this.callbacks, this.helpers, this.servicesManager);

        this.configurationTab.initializeComponent();


    }

    public void verifyApiKey() {
        if(callbacks.loadExtensionSetting(FLOW_API_KEY) == null || callbacks.loadExtensionSetting(FLOW_API_KEY).isEmpty()){
            this.rootTab.setSelectedIndex(CONFIG_INDEX);
        }
    }

    public ConfigurationTab getConfigurationTab() {
        return configurationTab;
    }

    public NewIssueTab getNewVulnerabilityTab() {
        return newIssueTab;
    }

    public AllocatedProjectsTab getAllocatedProjectsTab() {
        return allocatedProjectsTab;
    }

    public PlaybookTab getPlaybookTab() {
        return playbookTab;
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
