package view.issues_tab.listeners;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import models.auto_filter_combobox.AutoFilterComboboxModel;
import javax.swing.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

public class AutoFilterComboboxListener implements KeyListener {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JComboBox cboxVulnerabilityTemplates;
    private final JTextField cboxTextField;
    private AutoFilterComboboxModel autoFilterComboboxModel;
    private String lastFilter;
    private static boolean lastPressDeleteOrBackspace;
    private static boolean lastPressEnterOrEscape;

    public AutoFilterComboboxListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, JComboBox cboxVulnerabilityTemplates) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.cboxVulnerabilityTemplates = cboxVulnerabilityTemplates;
        this.cboxTextField = (JTextField) this.cboxVulnerabilityTemplates.getEditor().getEditorComponent();
        this.autoFilterComboboxModel = (AutoFilterComboboxModel) this.cboxVulnerabilityTemplates.getModel();
        lastFilter = "";
    }

    @Override
    public void keyTyped(KeyEvent e) {
        SwingUtilities.invokeLater(() -> {
            String pattern = cboxTextField.getText();

            if (lastFilter != null && !lastFilter.equals(pattern)) {
                lastFilter = pattern;

                autoFilterComboboxModel.filterList(pattern, !lastPressDeleteOrBackspace);


                if (autoFilterComboboxModel.getSize() != 1 || (autoFilterComboboxModel.getSize() == 1 && lastPressDeleteOrBackspace)) {
                    cboxTextField.setText(pattern);
                    cboxTextField.setCaretPosition(pattern.length());
                } else {
                    if (!pattern.isEmpty()) {
                        markDifferenceBetweenPattern(pattern);
                    }
                }
                hideAndShowPopup();

            }
        });
    }

    @Override
    public void keyPressed(KeyEvent e) {
        int keyCode = e.getKeyCode();
        lastPressDeleteOrBackspace = keyCode == KeyEvent.VK_BACK_SPACE || keyCode == KeyEvent.VK_DELETE;
        lastPressEnterOrEscape = keyCode == KeyEvent.VK_ENTER || keyCode == KeyEvent.VK_ESCAPE;
    }

    @Override
    public void keyReleased(KeyEvent e) {
        //do nothing
    }


    private void markDifferenceBetweenPattern(String pattern){
        if(lastPressDeleteOrBackspace){
            markText(cboxTextField.getText().length());
        }else{
            markText(pattern.length());
        }
    }

    private void markText(int start) {
        try{
            cboxTextField.setCaretPosition(cboxTextField.getText().length());
            cboxTextField.moveCaretPosition(start);
        }catch(IllegalArgumentException ignored){}

    }

    private synchronized void hideAndShowPopup(){
        if(cboxVulnerabilityTemplates.isPopupVisible()){
            cboxVulnerabilityTemplates.hidePopup();
        }
        if(!lastPressEnterOrEscape){
            cboxVulnerabilityTemplates.showPopup();
        }
    }

}

