package view.issues_tab;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;
import models.auto_filter_combobox.AutoFilterComboboxModel;
import models.project.Project;
import models.services_manager.ServicesManager;
import models.tabs_manager.TabsManager;
import models.vulnerability.Evidence;
import models.vulnerability.template.Template;
import models.vulnerability.Vulnerability;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpResponseException;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import services.ProjectService;
import services.TemplateService;
import services.VulnerabilityService;
import view.FathersComponentTab;
import view.info_template.ShowTemplateInformation;
import view.issues_tab.popup_menu.EvidencePopupMenu;
import view.issues_tab.listeners.AutoFilterComboboxListener;
import view.issues_tab.listeners.RefreshTemplatesButtonListener;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeListener;
import javax.swing.plaf.FontUIResource;
import javax.swing.text.StyleContext;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

public class NewIssueTab extends FathersComponentTab {
    private JComboBox cbVulnerabilityTemplates;
    private JRadioButton probabilityLowRButton;
    private JRadioButton probabilityMediumRButton;
    private JRadioButton probabilityHighRButton;
    private JRadioButton impactLowRButton;
    private JRadioButton impactMediumRButton;
    private JRadioButton impactHighRButton;
    private JEditorPane txtAreaDescription;
    private JButton btnRefreshVT;
    private JTextField txtFieldMethod;
    private JTextField txtFieldProtocol;
    private JTextField txtFieldUrl;
    private JTextArea txtAreaRequest;
    private JTextArea txtAreaResponse;
    private JList listParameters;
    private JButton btnRemoveParameter;
    private JButton btnRemoveAllParameters;
    private JButton btnRedactValue;
    private JScrollPane rootPanel;
    private JPanel rootPanel2;

    private TemplateService templateService;
    private VulnerabilityService vulnerabilityService;
    private ProjectService projectService;
    DefaultListModel<String> parametersListModel;
    private DefaultListModel<Evidence> evidenceListModel;
    private JEditorPane txtAreaStepsToReproduce;
    private JButton btnSubmitForm;
    private JButton btnClearForm;
    private JTextArea txtAreaImpact;
    private JRadioButton noCompromisedEnvironmentRButton;
    private JRadioButton yesCompromisedEnvironmentRButton;
    private JTabbedPane tabParametersRequestResponse;
    private JTabbedPane tabDescriptionImpactSteps;
    private JTextArea txtAreaCompromisedEnvironment;
    private JScrollPane scrollPaneCompromisedEnvironment;
    private JLabel lblImpact;
    private JLabel lblProbability;
    private JLabel lblMethod;
    private JLabel lblProtocol;
    private JLabel lblUrl;
    private JLabel lblVulnerabilityTemplate;
    private JLabel lblCompromisedEnvironment;
    private JList listEvidence;
    private JButton btnPreviewDescription;
    private JButton btnPreviewStepsToReproduce;
    private JLabel lblViewTemplate;
    private JButton btnImportParametersFromRequest;
    private JLabel lblCopyUri;
    private String evidencePlaceholder = "<html><b>Double left click</b> or <b>Right click</b> to add new evidence</html>";
    private AutoFilterComboboxModel autoFilterComboboxModel;
    private boolean fromContextMenu;
    boolean previewMarkdownDescription, previewMarkdownStepsToReproduce;
    HashMap<String, String> beforePreviewContents;
    Parser parser = Parser.builder().build();
    HtmlRenderer renderer = HtmlRenderer.builder().build();

    String defaultTabTitle = "<html>%s</html>";
    String defaultSelectedTabTitle = "<html><b>%s</b></html>";

    String defaultRequiredSelectedTabTitle = "<html><b><p style=\"color:red\">%s*</p></b></html>";
    String defaultRequiredTabTitle = "<html><p style=\"color:red\">%s*</p></html>";

    String defaultRequiredSelectedTabTitleDarkBackground = "<html><b><p style=\"color:orange\">%s*</p></b></html>";
    String defaultRequiredTabTitleDarkBackground = "<html><p style=\"color:orange\">%s*</p></html>";


    public NewIssueTab(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, ServicesManager servicesManager, TabsManager tabsManager) {
        super(callbacks, helpers, servicesManager, tabsManager);
        this.projectService = super.servicesManager.getProjectService();
        this.templateService = super.servicesManager.getTemplateService();
        this.vulnerabilityService = super.servicesManager.getVulnerabilityService();
        this.parametersListModel = new DefaultListModel<String>();
        this.evidenceListModel = new DefaultListModel<Evidence>();
        this.fromContextMenu = false;
        this.previewMarkdownDescription = false;
        this.previewMarkdownStepsToReproduce = false;
        this.beforePreviewContents = new HashMap<>();
    }

    public void initializeComponent() {


        // GUI initializer generated by IntelliJ IDEA GUI Designer
        // >>> IMPORTANT!! <<<
        // DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();

        /*
         * Color
         */

        this.setRootPanel(rootPanel2);
        this.setDefaultColors(lblVulnerabilityTemplate);

        if (this.isDarkBackground) {
            lblCopyUri.setIcon(new ImageIcon(getClass().getResource("/icons/copy-darkbkg.png")));
            btnSubmitForm.setForeground(this.rootPanel2.getForeground());
        } else {
            lblCopyUri.setIcon(new ImageIcon(getClass().getResource("/icons/copy-lightbkg.png")));
            btnSubmitForm.setForeground(new Color(255, 255, 255));
        }

        lblCopyUri.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals("foreground")) {
                if (this.isDarkBackground) {
                    lblCopyUri.setIcon(new ImageIcon(getClass().getResource("/icons/copy-darkbkg.png")));
                    btnSubmitForm.setForeground(this.rootPanel2.getForeground());
                } else {
                    btnSubmitForm.setForeground(new Color(255, 255, 255));
                    lblCopyUri.setIcon(new ImageIcon(getClass().getResource("/icons/copy-lightbkg.png")));
                }
            }
        });


        super.addLblBoldListener(lblVulnerabilityTemplate);
        super.addLblBoldListener(lblMethod);
        super.addLblBoldListener(lblProtocol);
        super.addLblBoldListener(lblImpact);
        super.addLblBoldListener(lblUrl);
        super.addLblBoldListener(lblProbability);
        super.addLblBoldListener(lblCompromisedEnvironment);

        /*
         * Definements
         */
        this.listParameters.setModel(parametersListModel);
        this.lblViewTemplate.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        this.lblViewTemplate.setEnabled(false);
        this.lblViewTemplate.setVisible(false);

        autoFilterComboboxModel = new AutoFilterComboboxModel();
        cbVulnerabilityTemplates.setModel(autoFilterComboboxModel);
        cbVulnerabilityTemplates.putClientProperty("JComboBox.isTableCellEditor", Boolean.TRUE);

        this.setBoldTitleTab(tabDescriptionImpactSteps);
        this.setBoldTitleTab(tabParametersRequestResponse);

        this.listEvidence.setModel(this.evidenceListModel);

        evidenceListModel.addElement(new Evidence(evidencePlaceholder, evidencePlaceholder));

        AutoFilterComboboxListener autoFilterComboboxListener = new AutoFilterComboboxListener(this.callbacks, this.helpers, cbVulnerabilityTemplates);

        JTextField textEditor = (JTextField) cbVulnerabilityTemplates.getEditor().getEditorComponent();
        textEditor.addKeyListener(autoFilterComboboxListener);

        /*
         * Action Listeners
         */

        cbVulnerabilityTemplates.addActionListener(e -> {
            switch (e.getActionCommand()) {
                case "comboBoxChanged": // monitorar para verificar o template escolhido
                    try {
                        Template templatePicked = (Template) autoFilterComboboxModel.getSelectedItem();
                        if (templatePicked != null) this.enableViewTemplate();
                        if (templatePicked != null && !templatePicked.getNotification()) {
                            this.notificationTemplateSelected(false);
                            switch (templatePicked.getProbability()) {
                                case "high" -> probabilityHighRButton.setSelected(true);
                                case "medium" -> probabilityMediumRButton.setSelected(true);
                                case "low" -> probabilityLowRButton.setSelected(true);
                            }
                            switch (templatePicked.getImpact()) {
                                case "high" -> impactHighRButton.setSelected(true);
                                case "medium" -> impactMediumRButton.setSelected(true);
                                case "low" -> impactLowRButton.setSelected(true);
                            }
                            cbVulnerabilityTemplates.requestFocus();
                        } else if (templatePicked != null && templatePicked.getNotification()) {
                            this.notificationTemplateSelected(true);
                        }
                    } catch (ClassCastException | NullPointerException ignored) {

                    }
                    break;
                case "comboBoxEdited":
                    break;

            }
        });

        /*
         * Tab Listeners
         */
        ChangeListener tabbChangeListener = e -> {
            if (e.getSource() instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) e.getSource();
                setBoldTitleTab(tabbedPane);
            }
        };

        tabParametersRequestResponse.addChangeListener(tabbChangeListener);
        tabDescriptionImpactSteps.addChangeListener(tabbChangeListener);


        /*
         * Mouse Listeners
         */
        lblCopyUri.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                StringSelection selection = new StringSelection(txtFieldUrl.getText());
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selection, selection);
                JOptionPane.showMessageDialog(rootPanel2, "Copied to clipboard!");
            }
        });

        final RefreshTemplatesButtonListener rtb = new RefreshTemplatesButtonListener(this.callbacks, this.helpers, cbVulnerabilityTemplates, this.templateService);
        btnRefreshVT.addActionListener(e -> new Thread(() -> rtb.mouseClicked(e)).start());

        lblViewTemplate.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                showInfoTemplateSelected();
            }
        });

        MouseAdapter rdButtonlistener = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                requestFocusNextFieldRadioButtons();
            }
        };
        probabilityLowRButton.addMouseListener(rdButtonlistener);
        probabilityMediumRButton.addMouseListener(rdButtonlistener);
        probabilityHighRButton.addMouseListener(rdButtonlistener);
        impactLowRButton.addMouseListener(rdButtonlistener);
        impactMediumRButton.addMouseListener(rdButtonlistener);
        impactHighRButton.addMouseListener(rdButtonlistener);

        btnRemoveParameter.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {

                List<Integer> indexes = Arrays.stream(listParameters.getSelectedIndices()).boxed().collect(Collectors.toList());
                Collections.reverse(indexes);

                for (int index :
                        indexes) {
                    parametersListModel.remove(index);
                }
            }
        });

        listEvidence.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e) || (SwingUtilities.isLeftMouseButton(e) && e.getClickCount() == 2)) {
                    EvidencePopupMenu evidencePopupMenu = new EvidencePopupMenu(NewIssueTab.this);
                    evidencePopupMenu.show((Component) e.getSource(), e.getX(), e.getY());
                }
            }
        });

        btnRemoveAllParameters.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                new Thread(() -> parametersListModel.clear()).start();
            }
        });

        btnRedactValue.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                new Thread(() -> {
                    int[] values = listParameters.getSelectedIndices();
                    for (int val :
                            values) {
                        String textContent = (String) listParameters.getModel().getElementAt(val);
                        parametersListModel.set(val, textContent.substring(0, textContent.indexOf("=")) + "=**REDACTED**");
                    }

                }).start();
            }
        });

        btnSubmitForm.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    Template templatePicked = (Template) autoFilterComboboxModel.getSelectedItem();
                    Vulnerability vulnerability;
                    if (templatePicked.getNotification()) {
                        vulnerability = validateNotification();
                    } else {
                        vulnerability = validateVulnerability();
                    }

                    if (vulnerability != null) {
                        Project workingProject = servicesManager.getProjectService().getWorkingProject();
                        if (workingProject != null) {
                            vulnerability.setAnalysisId(workingProject.getId());
                                new Thread(() -> {
                                    btnSubmitForm.setEnabled(false);
                                    try {
                                        vulnerabilityService.postVulnerability(vulnerability, NewIssueTab.this);
                                    } catch (FileNotFoundException fileNotFoundException) {
                                        JOptionPane.showMessageDialog(NewIssueTab.this.getRootPanel2(), "File not found!");
                                    } catch (HttpResponseException httpResponseException) {
                                        httpResponseException.printStackTrace();
                                    } catch (AuthenticationException authenticationException) {
                                        authenticationException.printStackTrace();
                                    }
                                    btnSubmitForm.setEnabled(true);
                                }).start();


                        } else {
                            tabsManager.setFocusToAllocatedProjectsTab();
                            JOptionPane.showMessageDialog(getRootPanel2(), "Working project not defined!");
                        }
                    }
                } catch (NullPointerException | ClassCastException ignored) {
                    getDefinedTemplateId();
                    JOptionPane.showMessageDialog(getRootPanel2(), "Template not defined!");
                }
            }
        });

        btnClearForm.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                clearForm();
            }
        });

        btnPreviewStepsToReproduce.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                previewMarkdownStepsToReproduce = !previewMarkdownStepsToReproduce;
                previewMarkDownText(previewMarkdownStepsToReproduce, "Steps to Reproduce", txtAreaStepsToReproduce);
            }
        });

        btnPreviewDescription.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                previewMarkdownDescription = !previewMarkdownDescription;
                previewMarkDownText(previewMarkdownDescription, "Description", txtAreaDescription);
            }
        });

        btnImportParametersFromRequest.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (!txtAreaRequest.getText().isEmpty()) {
                    List<IParameter> parameters = helpers.analyzeRequest(txtAreaRequest.getText().getBytes(StandardCharsets.UTF_8)).getParameters();
                    if (!parameters.isEmpty()) setListParameters(parameters);
                    else JOptionPane.showMessageDialog(getRootPanel2(), "This request has no parameters.");
                } else {
                    tabParametersRequestResponse.setSelectedIndex(1);
                    txtAreaRequest.requestFocus();
                    JOptionPane.showMessageDialog(getRootPanel2(), "Please define request!");
                }

            }
        });

        yesCompromisedEnvironmentRButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                new Thread(() -> {
                    noCompromisedEnvironmentRButton.setEnabled(false);
                    scrollPaneCompromisedEnvironment.setVisible(true);
                    txtAreaCompromisedEnvironment.setVisible(true);
                    txtAreaCompromisedEnvironment.requestFocus();
                    noCompromisedEnvironmentRButton.setEnabled(true);
                }).start();

            }
        });

        noCompromisedEnvironmentRButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                new Thread(() -> {
                    yesCompromisedEnvironmentRButton.setEnabled(false);
                    scrollPaneCompromisedEnvironment.setVisible(false);
                    txtAreaCompromisedEnvironment.setVisible(false);
                    requestFocusNextFieldRadioButtons();
                    yesCompromisedEnvironmentRButton.setEnabled(true);
                }).start();

            }
        });


    }

    private void previewMarkDownText(boolean markDownBooleanVariable, String markDownHashmapKey, JEditorPane txtArea) {
        if (markDownBooleanVariable) {
            String text = txtArea.getText();
            beforePreviewContents.put(markDownHashmapKey, text);
            Node document = parser.parse(text.replaceAll("<", "&lt;").replaceAll(">", "&gt;"));
            txtArea.setContentType("text/html");
            txtArea.setText(renderer.render(document).replaceAll("\\r?\\n", "<br/>").replaceFirst("<p>", "<p style=\"margin-top: 0\">"));
            txtArea.setEnabled(false);
        } else {
            txtArea.setContentType("text/plain");
            txtArea.setText(beforePreviewContents.get(markDownHashmapKey));
            txtArea.setEnabled(true);

        }
    }

    public void requestFocusNextFieldRadioButtons() {

        int selectedTab = tabDescriptionImpactSteps.getSelectedIndex();

        switch (selectedTab) {
            case 0 -> txtAreaDescription.requestFocus();
            case 1 -> txtAreaImpact.requestFocus();
            case 2 -> txtAreaStepsToReproduce.requestFocus();
            default -> txtFieldMethod.requestFocus();
        }
    }

    public void clearForm() {
        this.fromContextMenu = false;

        txtAreaDescription.setText("");
        if (!txtAreaDescription.isEnabled()) {
            txtAreaDescription.setEnabled(true);
            if (txtAreaDescription.getContentType().equals("text/html")) {
                txtAreaDescription.setContentType("text/plain");
            }
        }

        txtAreaImpact.setText("");

        txtAreaStepsToReproduce.setText("");
        if (!txtAreaStepsToReproduce.isEnabled()) {
            txtAreaStepsToReproduce.setEnabled(true);
            if (txtAreaStepsToReproduce.getContentType().equals("text/html")) {
                txtAreaStepsToReproduce.setContentType("text/plain");
            }

        }

        txtAreaCompromisedEnvironment.setText("");
        noCompromisedEnvironmentRButton.setSelected(true);
        scrollPaneCompromisedEnvironment.setVisible(false);
        txtAreaCompromisedEnvironment.setVisible(false);

        txtFieldMethod.setText("");
        if (!txtFieldMethod.isEnabled()) {
            txtFieldMethod.setEnabled(true);
        }

        txtFieldProtocol.setText("");
        if (!txtFieldProtocol.isEnabled()) {
            txtFieldProtocol.setEnabled(true);
        }

        txtFieldUrl.setText("");
        if (!txtFieldUrl.isEnabled()) {
            txtFieldUrl.setEnabled(true);
        }

        parametersListModel.clear();

        txtAreaRequest.setText("");
        if (!txtAreaRequest.isEnabled()) {
            txtAreaRequest.setEnabled(true);
        }

        txtAreaResponse.setText("");
        if (!txtAreaResponse.isEnabled()) {
            txtAreaResponse.setEnabled(true);
        }

        evidenceListModel.clear();
        listEvidence.putClientProperty("html.disable", Boolean.FALSE);
        evidenceListModel.addElement(new Evidence(evidencePlaceholder, evidencePlaceholder));

        this.notificationTemplateSelected(false);

        AutoFilterComboboxModel autoFilterComboboxModel = (AutoFilterComboboxModel) this.cbVulnerabilityTemplates.getModel();
        if (autoFilterComboboxModel.getSize() > 0) {
            autoFilterComboboxModel.filterList("", false);
            this.cbVulnerabilityTemplates.setSelectedIndex(0);
        }

        if (!this.btnSubmitForm.isEnabled()) {
            this.btnSubmitForm.setEnabled(true);
        }
    }

    private void setBoldTitleTab(JTabbedPane tabbedPane) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            if (tabbedPane.getTitleAt(i).contains("style=\"color:red\"") || tabbedPane.getTitleAt(i).contains("style=\"color:orange\"")) {
                if (i == tabbedPane.getSelectedIndex()) {
                    if (this.isDarkBackground) {
                        tabbedPane.setTitleAt(i, String.format(defaultRequiredSelectedTabTitle, this.cleanTabTitle(tabbedPane.getTitleAt(i))));
                    } else {
                        tabbedPane.setTitleAt(i, String.format(defaultRequiredSelectedTabTitleDarkBackground, this.cleanTabTitle(tabbedPane.getTitleAt(i))));
                    }

                } else {
                    if (this.isDarkBackground) {
                        tabbedPane.setTitleAt(i, String.format(defaultRequiredTabTitle, this.cleanTabTitle(tabbedPane.getTitleAt(i))));
                    } else {
                        tabbedPane.setTitleAt(i, String.format(defaultRequiredTabTitleDarkBackground, this.cleanTabTitle(tabbedPane.getTitleAt(i))));
                    }
                }
            } else {
                if (i == tabbedPane.getSelectedIndex()) {
                    tabbedPane.setTitleAt(i, String.format(defaultSelectedTabTitle, this.cleanTabTitle(tabbedPane.getTitleAt(i))));
                } else {
                    tabbedPane.setTitleAt(i, String.format(defaultTabTitle, this.cleanTabTitle(tabbedPane.getTitleAt(i))));
                }
            }
        }
    }

    private void setRequiredTitleTab(JTabbedPane tabbedPane, String tabTitle) {
        if (this.isDarkBackground) {
            setTabTitle(tabbedPane, tabTitle, defaultRequiredSelectedTabTitleDarkBackground, defaultRequiredTabTitleDarkBackground);
        } else {
            setTabTitle(tabbedPane, tabTitle, defaultRequiredSelectedTabTitle, defaultRequiredTabTitle);
        }
    }

    private void removeRequiredTitleTab(JTabbedPane tabbedPane, String tabTitle) {
        setTabTitle(tabbedPane, tabTitle, defaultSelectedTabTitle, defaultTabTitle);
    }

    private void setTabTitle(JTabbedPane tabbedPane, String tabTitle, String defaultSelectedTabTitle, String defaultTabTitle) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            if (tabbedPane.getTitleAt(i).contains(tabTitle)) {
                if (i == tabbedPane.getSelectedIndex()) {
                    tabbedPane.setTitleAt(i, String.format(defaultSelectedTabTitle, this.cleanTabTitle(tabbedPane.getTitleAt(i))));
                } else {
                    tabbedPane.setTitleAt(i, String.format(defaultTabTitle, this.cleanTabTitle(tabbedPane.getTitleAt(i))));
                }
            }
        }
    }

    private String cleanTabTitle(String tabTitle) {
        return tabTitle.replaceAll("(<.+?>)+", "").replace("*", "");
    }

    private void setLblRequired(JLabel label, String text) {
        label.setText(text + "*");
        if (this.isDarkBackground) {
            label.setForeground(new Color(225, 107, 46));
        } else {
            label.setForeground(Color.RED);
        }
    }

    private void setLblDefault(JLabel label) {
        label.setText(label.getText().replace("*", ""));
        label.setForeground(defaultLblColor);

    }

    private int getDefinedTemplateId() {
        int templateId = 0;
        try {
            templateId = ((Template) autoFilterComboboxModel.getSelectedItem()).getId();
        } catch (NullPointerException | ClassCastException ignored) {
        }

        if (templateId == 0) {
            this.setLblRequired(lblVulnerabilityTemplate, "Vulnerability Template");
            return 0;
        } else {
            this.setLblDefault(lblVulnerabilityTemplate);
            return templateId;
        }
    }

    private String getDefinedImpact() {
        if (this.impactHighRButton.isSelected()) {
            this.setLblDefault(lblImpact);
            return this.impactHighRButton.getText().toLowerCase();
        } else if (this.impactMediumRButton.isSelected()) {
            this.setLblDefault(lblImpact);
            return this.impactMediumRButton.getText().toLowerCase();
        } else if (this.impactLowRButton.isSelected()) {
            this.setLblDefault(lblImpact);
            return this.impactLowRButton.getText().toLowerCase();
        } else {
            this.setLblRequired(lblImpact, "Impact");
            return null;
        }
    }

    private String getDefinedProbability() {
        if (this.probabilityHighRButton.isSelected()) {
            this.setLblDefault(lblProbability);
            return this.probabilityHighRButton.getText().toLowerCase();
        } else if (this.probabilityMediumRButton.isSelected()) {
            this.setLblDefault(lblProbability);
            return this.probabilityMediumRButton.getText().toLowerCase();
        } else if (this.probabilityLowRButton.isSelected()) {
            this.setLblDefault(lblProbability);
            return this.probabilityLowRButton.getText().toLowerCase();
        } else {
            this.setLblRequired(lblProbability, "Probability");
            return null;
        }
    }

    private Boolean getCompromisedEnvironment() {
        if (this.yesCompromisedEnvironmentRButton.isSelected()) {
            return true;
        } else if (this.noCompromisedEnvironmentRButton.isSelected()) {
            return false;
        } else {
            return null;
        }
    }

    private String getCompromisedEnvironmentText() {
        if ((getCompromisedEnvironment() == null || getCompromisedEnvironment()) && txtAreaCompromisedEnvironment.getText().isEmpty()) {
            this.setLblRequired(lblCompromisedEnvironment, "Compromised Environment");
            return null;
        } else {
            this.setLblDefault(lblCompromisedEnvironment);
            return txtAreaCompromisedEnvironment.getText();
        }
    }

    private String getDescription() {
        if (txtAreaDescription.getText().isEmpty()) {
            this.setRequiredTitleTab(tabDescriptionImpactSteps, "Description");
            return null;
        } else {
            this.removeRequiredTitleTab(tabDescriptionImpactSteps, "Description");
            Node document = parser.parse(txtAreaDescription.getText().replaceAll("\\r?\\n", "</p><p>"));
            return renderer.render(document);
        }
    }

    private String getImpactDescription() {
        if (txtAreaImpact.getText().isEmpty()) {
            this.setRequiredTitleTab(tabDescriptionImpactSteps, "Impact");
            return null;
        } else {
            this.removeRequiredTitleTab(tabDescriptionImpactSteps, "Impact");
            return txtAreaImpact.getText();
        }
    }

    private String getStepsToReproduce() {
        if (txtAreaStepsToReproduce.getText().isEmpty()) {
            this.setRequiredTitleTab(tabDescriptionImpactSteps, "Steps to reproduce");
            return null;
        } else {
            this.removeRequiredTitleTab(tabDescriptionImpactSteps, "Steps to reproduce");
            Node document = parser.parse(txtAreaStepsToReproduce.getText().replaceAll("\\r?\\n", "</p><p>"));
            return renderer.render(document);
        }
    }

    private String getProtocol() {
        if (txtFieldProtocol.getText().isEmpty()) {
            this.setLblRequired(lblProtocol, "Protocol");
            return null;
        } else {
            this.setLblDefault(lblProtocol);
            return txtFieldProtocol.getText();
        }
    }

    private String getMethod() {
        if (txtFieldMethod.getText().isEmpty()) {
            this.setLblRequired(lblMethod, "Method");
            return null;
        } else {
            this.setLblDefault(lblMethod);
            return txtFieldMethod.getText();

        }
    }

    private String getUrl() {
        if (txtFieldUrl.getText().isEmpty()) {
            this.setLblRequired(lblUrl, "URI");
            return null;
        } else {
            this.setLblDefault(lblUrl);
            return txtFieldUrl.getText();
        }
    }

    private String getRequest() {
        if (txtAreaRequest.getText().isEmpty()) {
            this.setRequiredTitleTab(tabParametersRequestResponse, "Request");
            return null;
        } else {
            this.removeRequiredTitleTab(tabParametersRequestResponse, "Request");
            return txtAreaRequest.getText().replace("\\", "\\\\");
        }
    }

    private String getResponse() {
        if (txtAreaResponse.getText().isEmpty()) {
            this.setRequiredTitleTab(tabParametersRequestResponse, "Response");
            return null;
        } else {
            this.removeRequiredTitleTab(tabParametersRequestResponse, "Response");
            return txtAreaResponse.getText().replace("\\", "\\\\");
        }
    }

    private ArrayList<Evidence> getEvidence() {
        ArrayList<Evidence> evidenceArrayList = new ArrayList<>();

        if (evidenceListModel.get(0).getName().equals(evidencePlaceholder)) {
            this.setRequiredTitleTab(tabDescriptionImpactSteps, "Evidence");
            return null;
        }

        for (int i = 0; i < evidenceListModel.getSize(); i++) {
            evidenceArrayList.add(evidenceListModel.get(i));
        }

        this.removeRequiredTitleTab(tabDescriptionImpactSteps, "Evidence");
        return evidenceArrayList;

    }

    public void addEvidence(Evidence evidence) {
        if (evidence.validateExtension()) {
            if (evidenceListModel.get(0).getName().equals(evidencePlaceholder)) {
                evidenceListModel.clear();
                listEvidence.putClientProperty("html.disable", Boolean.TRUE);
            }
            evidenceListModel.addElement(evidence);
        } else {
            JOptionPane.showMessageDialog(this.getRootPanel2(), "Invalid extension!\n" +
                    "Please use : .pdf .zip .jpg .jpeg .png .txt .doc .xls .rar .docx .gif");
        }
    }

    public void removeSelectedEvidence() {
        if (this.listEvidence.getSelectedIndex() != -1) {
            this.evidenceListModel.remove(this.listEvidence.getSelectedIndex());
        }

        if (evidenceListModel.size() == 0) {
            listEvidence.putClientProperty("html.disable", Boolean.FALSE);
            evidenceListModel.addElement(new Evidence(evidencePlaceholder, evidencePlaceholder));
        }
    }

    private String getParameterListAsString() {
        StringBuilder toReturn = new StringBuilder();
        for (int i = 0; i < parametersListModel.getSize(); i++) {
            toReturn.append(parametersListModel.get(i)).append("\n");
        }
        return toReturn.toString().trim();
    }

    public void setRequest(String req) {
        if (this.txtAreaRequest.isEnabled()) this.txtAreaRequest.setEnabled(false);
        this.txtAreaRequest.setText(req);
        this.txtAreaRequest.setCaretPosition(0);
    }

    public void setResponse(String resp) {
        if (this.txtAreaResponse.isEnabled()) this.txtAreaResponse.setEnabled(false);
        this.txtAreaResponse.setText(resp);
        this.txtAreaResponse.setCaretPosition(0);
    }

    public void setTxtFieldMethod(String method) {
        if (this.txtFieldMethod.isEnabled()) this.txtFieldMethod.setEnabled(false);
        this.txtFieldMethod.setText(method);
    }

    public void setTxtFieldUrl(String url) {
        if (this.txtFieldUrl.isEnabled()) this.txtFieldUrl.setEnabled(false);
        this.txtFieldUrl.setText(url);
    }

    public void setTxtFieldProtocol(String prot) {
        if (this.txtFieldProtocol.isEnabled()) this.txtFieldProtocol.setEnabled(false);
        this.txtFieldProtocol.setText(prot);
    }

    public void setListParameters(List<IParameter> params) {
        this.parametersListModel.clear();

        for (IParameter param : params) {
            this.parametersListModel.addElement(param.getName() + "=" + param.getValue());
        }
    }

    public Vulnerability validateNotification() {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setNotification(true);

        int templateId = getDefinedTemplateId();
        if (templateId != 0) {
            vulnerability.setVulnerabilityTemplateId(templateId);
        }

        String definedDescription = getDescription();
        if (definedDescription != null) {
            vulnerability.setDescription(definedDescription);
        }

        ArrayList<Evidence> definedEvidences = getEvidence();
        if (definedEvidences != null) {
            vulnerability.setVulnerabilityArchives(definedEvidences);
        }

        if (templateId == 0 ||
                definedDescription == null ||
                definedEvidences == null) {
            JOptionPane.showMessageDialog(rootPanel2, "Required camps are missing!");
            return null;
        } else {
            return vulnerability;
        }

    }

    public Vulnerability validateVulnerability() {
        Vulnerability vulnerability = new Vulnerability();

        int templateId = getDefinedTemplateId();
        if (templateId != 0) {
            vulnerability.setVulnerabilityTemplateId(getDefinedTemplateId());
        }

        String definedImpact = getDefinedImpact();
        if (definedImpact != null) {
            vulnerability.setImpact(definedImpact);
        }


        String definedProbability = getDefinedProbability();
        if (definedProbability != null) {
            vulnerability.setProbability(definedProbability);
        }

        Boolean definedCompromisedEnvironment = getCompromisedEnvironment();
        if (definedCompromisedEnvironment != null) {
            vulnerability.setInvaded(definedCompromisedEnvironment);
        }

        String definedCompromisedEnvironmentText = getCompromisedEnvironmentText();
        if (definedCompromisedEnvironmentText != null) {
            vulnerability.setInvadedEnvironmentDescription(definedCompromisedEnvironmentText);
        }

        String definedDescription = getDescription();
        if (definedDescription != null) {
            vulnerability.setDescription(definedDescription);
        }

        String definedImpactDescription = getImpactDescription();
        if (definedImpactDescription != null) {
            vulnerability.setImpactResume(definedImpactDescription);
        }

        String definedStepsToReproduce = getStepsToReproduce();
        if (definedStepsToReproduce != null) {
            vulnerability.setWebSteps(definedStepsToReproduce);
        }

        ArrayList<Evidence> definedEvidences = getEvidence();
        if (definedEvidences != null) {
            vulnerability.setVulnerabilityArchives(definedEvidences);
        }

        String definedMethod = getMethod();
        if (definedMethod != null) {
            vulnerability.setWebMethod(definedMethod);
        }

        String definedProtocol = getProtocol();
        if (definedProtocol != null) {
            vulnerability.setWebProtocol(definedProtocol);
        }

        String definedUrl = getUrl();
        if (definedUrl != null) {
            vulnerability.setWebUrl(definedUrl);
        }

        vulnerability.setWebParameters(getParameterListAsString()); // it is not required, so it can be empty.

        String definedRequest = getRequest();
        if (definedRequest != null) {
            vulnerability.setWebRequest(definedRequest);
        }

        String definedResponse = getResponse();
        if (definedResponse != null) {
            vulnerability.setWebResponse(definedResponse);
        }

        if (templateId == 0 ||
                definedImpact == null ||
                definedProbability == null ||
                definedCompromisedEnvironment == null ||
                definedCompromisedEnvironmentText == null ||
                definedDescription == null ||
                definedImpactDescription == null ||
                definedStepsToReproduce == null ||
                definedEvidences == null ||
                definedMethod == null ||
                definedProtocol == null ||
                definedUrl == null ||
                definedRequest == null ||
                definedResponse == null) {
            JOptionPane.showMessageDialog(rootPanel2, "Required camps are missing!");
            return null;
        } else {
            return vulnerability;
        }

    }

    private void notificationTemplateSelected(boolean isSelected) {
        probabilityHighRButton.setEnabled(!isSelected);
        probabilityMediumRButton.setEnabled(!isSelected);
        probabilityLowRButton.setEnabled(!isSelected);
        impactHighRButton.setEnabled(!isSelected);
        impactMediumRButton.setEnabled(!isSelected);
        impactLowRButton.setEnabled(!isSelected);
        yesCompromisedEnvironmentRButton.setEnabled(!isSelected);
        noCompromisedEnvironmentRButton.setEnabled(!isSelected);
        txtAreaImpact.setEnabled(!isSelected);
        txtAreaStepsToReproduce.setEnabled(!isSelected);
        btnPreviewStepsToReproduce.setEnabled(!isSelected);

        tabParametersRequestResponse.setEnabled(!isSelected);
        listParameters.setEnabled(!isSelected);
        btnRemoveParameter.setEnabled(!isSelected);
        btnRemoveAllParameters.setEnabled(!isSelected);
        btnRedactValue.setEnabled(!isSelected);
        btnImportParametersFromRequest.setEnabled(!isSelected);

        if (this.fromContextMenu) {
            txtFieldMethod.setEnabled(false);
            txtFieldProtocol.setEnabled(false);
            txtFieldUrl.setEnabled(false);
        } else {
            txtFieldMethod.setEnabled(!isSelected);
            txtFieldProtocol.setEnabled(!isSelected);
            txtFieldUrl.setEnabled(!isSelected);
        }

    }

    private void enableViewTemplate() {
        this.lblViewTemplate.setEnabled(true);
        this.lblViewTemplate.setVisible(true);
    }

    private void showInfoTemplateSelected() {
        Dimension defaultDimension = (Dimension) UIManager.get("OptionPane.minimumSize");
        try {
            Template templatePicked = (Template) autoFilterComboboxModel.getSelectedItem();

            UIManager.put("OptionPane.minimumSize", new Dimension(800, 800));

            ShowTemplateInformation showTemplateInformation = new ShowTemplateInformation();
            showTemplateInformation.setTitle(templatePicked.getTitle());
            showTemplateInformation.setCategories(templatePicked.getCategories());
            showTemplateInformation.setTxtFieldPatterns(templatePicked.getPatterns());
            showTemplateInformation.setVulnerabilityText(templatePicked.getDescription());
            showTemplateInformation.setVulnerabilityReferences(templatePicked.getReference());

            JOptionPane.showMessageDialog(this.getRootPanel2(), showTemplateInformation.$$$getRootComponent$$$(), "Template information", JOptionPane.PLAIN_MESSAGE);
        } catch (ClassCastException | NullPointerException ignored) {
            UIManager.put("OptionPane.minimumSize", defaultDimension);
            JOptionPane.showMessageDialog(this.getRootPanel2(), "Something went wrong, please try again.");
        } finally {
            UIManager.put("OptionPane.minimumSize", defaultDimension);
        }


    }

    public DefaultListModel<Evidence> getEvidenceListModel() {
        return evidenceListModel;
    }

    public void setEvidenceListModel(DefaultListModel<Evidence> evidenceListModel) {
        this.evidenceListModel = evidenceListModel;
    }

    public JList getListEvidence() {
        return listEvidence;
    }

    public void setListEvidence(JList listEvidence) {
        this.listEvidence = listEvidence;
    }


    public boolean isFromContextMenu() {
        return fromContextMenu;
    }

    public void setFromContextMenu(boolean fromContextMenu) {
        this.fromContextMenu = fromContextMenu;
    }

    public JPanel getRootPanel2() {
        return rootPanel2;
    }

    public JButton getBtnSubmitForm() {
        return btnSubmitForm;
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        rootPanel = new JScrollPane();
        rootPanel2 = new JPanel();
        rootPanel2.setLayout(new FormLayout("fill:max(d;4px):noGrow,left:75dlu:grow,fill:138px:noGrow,left:16dlu:noGrow,fill:88px:noGrow,left:5dlu:noGrow,fill:58px:noGrow,left:7dlu:noGrow,fill:max(d;4px):noGrow,left:14dlu:noGrow,left:10dlu:noGrow,fill:255px:noGrow,left:13dlu:noGrow,fill:10px:noGrow,left:27dlu:noGrow,left:4dlu:noGrow,fill:97px:grow", "center:13px:noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,center:24px:noGrow,center:max(d;4px):noGrow,center:max(d;4px):noGrow,center:15px:noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,top:5dlu:noGrow,center:58px:noGrow,center:9px:noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,center:138px:grow,top:6dlu:noGrow,center:11px:noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,top:35dlu:noGrow,center:13px:noGrow,center:11px:noGrow,top:4dlu:noGrow,center:206px:grow,center:max(d;4px):noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,center:max(d;4px):noGrow"));
        rootPanel.setViewportView(rootPanel2);
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new FormLayout("fill:575px:grow,left:7dlu:noGrow,fill:max(d;4px):noGrow", "center:d:noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow"));
        CellConstraints cc = new CellConstraints();
        rootPanel2.add(panel1, cc.xyw(3, 3, 13));
        lblVulnerabilityTemplate = new JLabel();
        Font lblVulnerabilityTemplateFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblVulnerabilityTemplate.getFont());
        if (lblVulnerabilityTemplateFont != null) lblVulnerabilityTemplate.setFont(lblVulnerabilityTemplateFont);
        lblVulnerabilityTemplate.setText("Vulnerability Template");
        panel1.add(lblVulnerabilityTemplate, cc.xy(1, 1));
        cbVulnerabilityTemplates = new JComboBox();
        cbVulnerabilityTemplates.setEditable(true);
        cbVulnerabilityTemplates.putClientProperty("html.disable", Boolean.TRUE);
        panel1.add(cbVulnerabilityTemplates, cc.xy(1, 3));
        btnRefreshVT = new JButton();
        btnRefreshVT.setText("Load templates");
        panel1.add(btnRefreshVT, cc.xy(3, 3));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new FormLayout("fill:65px:noGrow,left:5dlu:noGrow,fill:70px:noGrow,left:6dlu:noGrow,fill:43px:noGrow,left:10dlu:noGrow,fill:465px:grow,fill:max(d;4px):noGrow,fill:17px:noGrow", "center:max(d;4px):noGrow,top:4dlu:noGrow,center:16px:noGrow,top:5dlu:noGrow,center:30px:noGrow"));
        rootPanel2.add(panel2, cc.xywh(3, 18, 13, 5));
        lblMethod = new JLabel();
        Font lblMethodFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblMethod.getFont());
        if (lblMethodFont != null) lblMethod.setFont(lblMethodFont);
        lblMethod.setText("Method");
        panel2.add(lblMethod, cc.xyw(1, 3, 2));
        txtFieldMethod = new JTextField();
        txtFieldMethod.putClientProperty("html.disable", Boolean.TRUE);
        panel2.add(txtFieldMethod, cc.xy(1, 5, CellConstraints.FILL, CellConstraints.DEFAULT));
        lblProtocol = new JLabel();
        Font lblProtocolFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblProtocol.getFont());
        if (lblProtocolFont != null) lblProtocol.setFont(lblProtocolFont);
        lblProtocol.setText("Protocol");
        panel2.add(lblProtocol, cc.xyw(3, 3, 2));
        lblUrl = new JLabel();
        Font lblUrlFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblUrl.getFont());
        if (lblUrlFont != null) lblUrl.setFont(lblUrlFont);
        lblUrl.setText("URI");
        panel2.add(lblUrl, cc.xy(5, 3));
        txtFieldProtocol = new JTextField();
        txtFieldProtocol.putClientProperty("html.disable", Boolean.TRUE);
        panel2.add(txtFieldProtocol, cc.xy(3, 5, CellConstraints.FILL, CellConstraints.DEFAULT));
        txtFieldUrl = new JTextField();
        txtFieldUrl.putClientProperty("html.disable", Boolean.TRUE);
        panel2.add(txtFieldUrl, cc.xyw(5, 5, 3, CellConstraints.FILL, CellConstraints.DEFAULT));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new FormLayout("fill:16px:grow", "center:d:grow"));
        panel2.add(panel3, cc.xy(9, 5, CellConstraints.DEFAULT, CellConstraints.FILL));
        lblCopyUri = new JLabel();
        lblCopyUri.setIcon(new ImageIcon(getClass().getResource("/icons/copy-lightbkg.png")));
        lblCopyUri.setText("");
        lblCopyUri.setToolTipText("Copy URI");
        panel3.add(lblCopyUri, cc.xy(1, 1));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new FormLayout("fill:138px:noGrow,left:16dlu:noGrow,fill:88px:noGrow,left:5dlu:noGrow,fill:58px:noGrow,left:7dlu:noGrow,fill:max(d;4px):noGrow,left:14dlu:noGrow,left:199dlu:noGrow", "center:max(d;4px):noGrow,center:15px:noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,top:5dlu:noGrow,center:54px:noGrow"));
        rootPanel2.add(panel4, cc.xywh(3, 6, 13, 7));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new FormLayout("fill:86px:noGrow,left:8dlu:noGrow,fill:110px:noGrow,left:6dlu:noGrow,fill:105px:noGrow", "center:max(d;4px):noGrow,top:4dlu:noGrow,center:21px:noGrow"));
        panel4.add(panel5, cc.xywh(1, 1, 6, 6));
        probabilityLowRButton = new JRadioButton();
        probabilityLowRButton.setText("Low");
        panel5.add(probabilityLowRButton, cc.xy(1, 3));
        probabilityMediumRButton = new JRadioButton();
        probabilityMediumRButton.setText("Medium");
        panel5.add(probabilityMediumRButton, cc.xy(3, 3));
        probabilityHighRButton = new JRadioButton();
        probabilityHighRButton.setText("High");
        panel5.add(probabilityHighRButton, cc.xy(5, 3));
        lblProbability = new JLabel();
        Font lblProbabilityFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblProbability.getFont());
        if (lblProbabilityFont != null) lblProbability.setFont(lblProbabilityFont);
        lblProbability.setText("Probability");
        panel5.add(lblProbability, cc.xyw(1, 1, 3));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new FormLayout("fill:86px:noGrow,left:8dlu:noGrow,fill:110px:noGrow,left:7dlu:noGrow,fill:105px:noGrow", "center:max(d;4px):noGrow,top:4dlu:noGrow,center:21px:noGrow"));
        panel4.add(panel6, cc.xyw(1, 7, 6));
        impactLowRButton = new JRadioButton();
        impactLowRButton.setText("Low");
        panel6.add(impactLowRButton, cc.xy(1, 3));
        impactMediumRButton = new JRadioButton();
        impactMediumRButton.setText("Medium");
        panel6.add(impactMediumRButton, cc.xy(3, 3));
        impactHighRButton = new JRadioButton();
        impactHighRButton.setText("High");
        panel6.add(impactHighRButton, cc.xy(5, 3));
        lblImpact = new JLabel();
        Font lblImpactFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblImpact.getFont());
        if (lblImpactFont != null) lblImpact.setFont(lblImpactFont);
        lblImpact.setText("Impact");
        panel6.add(lblImpact, cc.xyw(1, 1, 3));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new FormLayout("fill:52px:noGrow,left:6dlu:noGrow,fill:294px:noGrow", "center:max(d;4px):noGrow,top:7dlu:noGrow,center:27px:noGrow,top:7dlu:noGrow,center:25px:noGrow"));
        panel4.add(panel7, cc.xywh(9, 1, 1, 7));
        noCompromisedEnvironmentRButton = new JRadioButton();
        noCompromisedEnvironmentRButton.setSelected(true);
        noCompromisedEnvironmentRButton.setText("No");
        panel7.add(noCompromisedEnvironmentRButton, cc.xyw(1, 5, 2));
        lblCompromisedEnvironment = new JLabel();
        Font lblCompromisedEnvironmentFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblCompromisedEnvironment.getFont());
        if (lblCompromisedEnvironmentFont != null) lblCompromisedEnvironment.setFont(lblCompromisedEnvironmentFont);
        lblCompromisedEnvironment.setText("Compromised Environment");
        panel7.add(lblCompromisedEnvironment, cc.xyw(1, 1, 3));
        yesCompromisedEnvironmentRButton = new JRadioButton();
        yesCompromisedEnvironmentRButton.setText("Yes");
        panel7.add(yesCompromisedEnvironmentRButton, cc.xyw(1, 3, 2));
        scrollPaneCompromisedEnvironment = new JScrollPane();
        scrollPaneCompromisedEnvironment.setVisible(false);
        panel7.add(scrollPaneCompromisedEnvironment, cc.xywh(3, 3, 1, 3, CellConstraints.FILL, CellConstraints.FILL));
        txtAreaCompromisedEnvironment = new JTextArea();
        txtAreaCompromisedEnvironment.setLineWrap(true);
        txtAreaCompromisedEnvironment.setVisible(false);
        scrollPaneCompromisedEnvironment.setViewportView(txtAreaCompromisedEnvironment);
        final JSeparator separator1 = new JSeparator();
        separator1.setOrientation(1);
        panel4.add(separator1, cc.xywh(7, 1, 1, 7, CellConstraints.FILL, CellConstraints.FILL));
        tabDescriptionImpactSteps = new JTabbedPane();
        rootPanel2.add(tabDescriptionImpactSteps, cc.xywh(3, 14, 13, 4, CellConstraints.DEFAULT, CellConstraints.FILL));
        tabDescriptionImpactSteps.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new FormLayout("fill:d:grow", "center:84px:grow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow"));
        tabDescriptionImpactSteps.addTab("Description", panel8);
        final JScrollPane scrollPane1 = new JScrollPane();
        panel8.add(scrollPane1, cc.xy(1, 1, CellConstraints.FILL, CellConstraints.FILL));
        txtAreaDescription = new JEditorPane();
        txtAreaDescription.setContentType("text/plain");
        scrollPane1.setViewportView(txtAreaDescription);
        btnPreviewDescription = new JButton();
        btnPreviewDescription.setText("Preview");
        panel8.add(btnPreviewDescription, cc.xy(1, 3));
        final JPanel panel9 = new JPanel();
        panel9.setLayout(new FormLayout("fill:d:grow", "center:84px:grow"));
        tabDescriptionImpactSteps.addTab("Impact", panel9);
        final JScrollPane scrollPane2 = new JScrollPane();
        panel9.add(scrollPane2, cc.xy(1, 1, CellConstraints.FILL, CellConstraints.FILL));
        txtAreaImpact = new JTextArea();
        txtAreaImpact.setLineWrap(true);
        txtAreaImpact.setText("");
        txtAreaImpact.putClientProperty("html.disable", Boolean.TRUE);
        scrollPane2.setViewportView(txtAreaImpact);
        final JPanel panel10 = new JPanel();
        panel10.setLayout(new FormLayout("fill:d:grow", "center:84px:grow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow"));
        tabDescriptionImpactSteps.addTab("Steps to reproduce", panel10);
        final JScrollPane scrollPane3 = new JScrollPane();
        panel10.add(scrollPane3, cc.xy(1, 1, CellConstraints.FILL, CellConstraints.FILL));
        txtAreaStepsToReproduce = new JEditorPane();
        txtAreaStepsToReproduce.setContentType("text/plain");
        scrollPane3.setViewportView(txtAreaStepsToReproduce);
        btnPreviewStepsToReproduce = new JButton();
        btnPreviewStepsToReproduce.setText("Preview");
        panel10.add(btnPreviewStepsToReproduce, cc.xy(1, 3));
        final JPanel panel11 = new JPanel();
        panel11.setLayout(new FormLayout("fill:708px:grow", "center:125px:grow"));
        tabDescriptionImpactSteps.addTab("Evidence", panel11);
        final JScrollPane scrollPane4 = new JScrollPane();
        panel11.add(scrollPane4, cc.xy(1, 1, CellConstraints.DEFAULT, CellConstraints.FILL));
        listEvidence = new JList();
        listEvidence.putClientProperty("List.isFileList", Boolean.TRUE);
        listEvidence.putClientProperty("html.disable", Boolean.FALSE);
        scrollPane4.setViewportView(listEvidence);
        tabParametersRequestResponse = new JTabbedPane();
        Font tabParametersRequestResponseFont = this.$$$getFont$$$(null, -1, -1, tabParametersRequestResponse.getFont());
        if (tabParametersRequestResponseFont != null)
            tabParametersRequestResponse.setFont(tabParametersRequestResponseFont);
        tabParametersRequestResponse.setTabLayoutPolicy(0);
        tabParametersRequestResponse.setTabPlacement(1);
        rootPanel2.add(tabParametersRequestResponse, cc.xywh(3, 24, 13, 3, CellConstraints.DEFAULT, CellConstraints.FILL));
        tabParametersRequestResponse.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        final JPanel panel12 = new JPanel();
        panel12.setLayout(new FormLayout("fill:713px:grow", "top:148px:grow,center:max(d;4px):noGrow"));
        Font panel12Font = this.$$$getFont$$$(null, -1, -1, panel12.getFont());
        if (panel12Font != null) panel12.setFont(panel12Font);
        tabParametersRequestResponse.addTab("Parameters", panel12);
        final JScrollPane scrollPane5 = new JScrollPane();
        panel12.add(scrollPane5, cc.xy(1, 1, CellConstraints.FILL, CellConstraints.FILL));
        listParameters = new JList();
        listParameters.putClientProperty("html.disable", Boolean.TRUE);
        scrollPane5.setViewportView(listParameters);
        final JPanel panel13 = new JPanel();
        panel13.setLayout(new FormLayout("fill:100px:noGrow,left:4dlu:noGrow,fill:116px:noGrow,left:4dlu:noGrow,fill:max(d;4px):noGrow,left:4dlu:noGrow,fill:max(d;4px):noGrow", "center:46px:noGrow"));
        panel12.add(panel13, cc.xy(1, 2, CellConstraints.DEFAULT, CellConstraints.BOTTOM));
        btnRemoveAllParameters = new JButton();
        btnRemoveAllParameters.setText("Remove All");
        panel13.add(btnRemoveAllParameters, cc.xy(3, 1));
        btnRemoveParameter = new JButton();
        btnRemoveParameter.setText("Remove");
        panel13.add(btnRemoveParameter, cc.xy(1, 1));
        btnRedactValue = new JButton();
        btnRedactValue.setText("Redact Value");
        panel13.add(btnRedactValue, cc.xy(5, 1));
        btnImportParametersFromRequest = new JButton();
        btnImportParametersFromRequest.setText("Import from request");
        panel13.add(btnImportParametersFromRequest, cc.xy(7, 1));
        final JPanel panel14 = new JPanel();
        panel14.setLayout(new FormLayout("fill:d:grow", "center:193px:grow"));
        tabParametersRequestResponse.addTab("Request", panel14);
        final JScrollPane scrollPane6 = new JScrollPane();
        panel14.add(scrollPane6, cc.xy(1, 1, CellConstraints.DEFAULT, CellConstraints.FILL));
        txtAreaRequest = new JTextArea();
        txtAreaRequest.putClientProperty("html.disable", Boolean.TRUE);
        scrollPane6.setViewportView(txtAreaRequest);
        final JPanel panel15 = new JPanel();
        panel15.setLayout(new FormLayout("fill:270px:grow", "center:193px:grow"));
        tabParametersRequestResponse.addTab("Response", panel15);
        final JScrollPane scrollPane7 = new JScrollPane();
        panel15.add(scrollPane7, cc.xy(1, 1, CellConstraints.DEFAULT, CellConstraints.FILL));
        txtAreaResponse = new JTextArea();
        txtAreaResponse.putClientProperty("html.disable", Boolean.TRUE);
        scrollPane7.setViewportView(txtAreaResponse);
        final JPanel panel16 = new JPanel();
        panel16.setLayout(new FormLayout("fill:max(d;4px):noGrow,left:4dlu:grow,fill:max(d;4px):noGrow", "center:d:noGrow"));
        rootPanel2.add(panel16, cc.xyw(3, 30, 13));
        btnClearForm = new JButton();
        btnClearForm.setText("Clear");
        panel16.add(btnClearForm, cc.xy(1, 1, CellConstraints.RIGHT, CellConstraints.DEFAULT));
        btnSubmitForm = new JButton();
        btnSubmitForm.setBackground(new Color(-14260834));
        btnSubmitForm.setForeground(new Color(-4473925));
        btnSubmitForm.setText("Submit");
        panel16.add(btnSubmitForm, cc.xy(3, 1));
        final JPanel panel17 = new JPanel();
        panel17.setLayout(new FormLayout("left:35px:noGrow", "center:d:grow"));
        rootPanel2.add(panel17, cc.xy(3, 4));
        lblViewTemplate = new JLabel();
        lblViewTemplate.setText("<html><u>[View]</u></html>");
        panel17.add(lblViewTemplate, cc.xy(1, 1));
        ButtonGroup buttonGroup;
        buttonGroup = new ButtonGroup();
        buttonGroup.add(probabilityLowRButton);
        buttonGroup.add(probabilityMediumRButton);
        buttonGroup.add(probabilityHighRButton);
        buttonGroup = new ButtonGroup();
        buttonGroup.add(impactLowRButton);
        buttonGroup.add(impactMediumRButton);
        buttonGroup.add(impactHighRButton);
        buttonGroup = new ButtonGroup();
        buttonGroup.add(noCompromisedEnvironmentRButton);
        buttonGroup.add(yesCompromisedEnvironmentRButton);
    }

    /**
     * @noinspection ALL
     */
    private Font $$$getFont$$$(String fontName, int style, int size, Font currentFont) {
        if (currentFont == null) return null;
        String resultName;
        if (fontName == null) {
            resultName = currentFont.getName();
        } else {
            Font testFont = new Font(fontName, Font.PLAIN, 10);
            if (testFont.canDisplay('a') && testFont.canDisplay('1')) {
                resultName = fontName;
            } else {
                resultName = currentFont.getName();
            }
        }
        Font font = new Font(resultName, style >= 0 ? style : currentFont.getStyle(), size >= 0 ? size : currentFont.getSize());
        boolean isMac = System.getProperty("os.name", "").toLowerCase(Locale.ENGLISH).startsWith("mac");
        Font fontWithFallback = isMac ? new Font(font.getFamily(), font.getStyle(), font.getSize()) : new StyleContext().getFont(font.getFamily(), font.getStyle(), font.getSize());
        return fontWithFallback instanceof FontUIResource ? fontWithFallback : new FontUIResource(fontWithFallback);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }


}

