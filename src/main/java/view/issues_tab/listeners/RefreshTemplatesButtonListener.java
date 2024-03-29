package view.issues_tab.listeners;



import models.auto_filter_combobox.AutoFilterComboboxModel;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import models.issue.template.Template;
import services.TemplateService;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Set;

public class RefreshTemplatesButtonListener implements ActionListener {

    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JComboBox cboxVulnerabilityTemplates;
    private final TemplateService templateService;

    public RefreshTemplatesButtonListener( final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, JComboBox cboxVulnerabilityTemplates, TemplateService templateService) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.cboxVulnerabilityTemplates = cboxVulnerabilityTemplates;
        this.templateService = templateService;
    }

    public void mouseClicked(ActionEvent e) {
        JButton refreshButton = (JButton) e.getSource();
        if(!refreshButton.isEnabled()) {
            return;
        }
        refreshButton.setEnabled(false);
        Set<Template> templatesArray = this.templateService.getAllTemplates();

        this.cboxVulnerabilityTemplates.removeAllItems();
        AutoFilterComboboxModel autoFilterComboboxModel = (AutoFilterComboboxModel) this.cboxVulnerabilityTemplates.getModel();
        autoFilterComboboxModel.setTemplatesList(new ArrayList<>(templatesArray));

        if(templatesArray.size() != 0){
            this.cboxVulnerabilityTemplates.setSelectedIndex(0);
        }
        this.markText();
        refreshButton.setText("Reload templates");
        refreshButton.setEnabled(true);

    }

    @Override
    public void actionPerformed(ActionEvent e) {

    }

    private void markText() {
        JTextField textField = (JTextField) cboxVulnerabilityTemplates.getEditor().getEditorComponent();
        textField.setCaretPosition(textField.getText().length());
        textField.moveCaretPosition(0);
    }
}
