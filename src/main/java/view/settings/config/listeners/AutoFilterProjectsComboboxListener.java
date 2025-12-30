package view.settings.config.listeners;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import models.auto_filter_combobox.AutoFilterProjectsComboboxModel;

import javax.swing.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

public class AutoFilterProjectsComboboxListener implements KeyListener {

    private final JComboBox cbProjects;
    private final JTextField cbTextField;
    private final AutoFilterProjectsComboboxModel autoFilterComboboxModel;
    private String lastFilter;
    private static boolean lastPressDeleteOrBackspace;
    private static boolean lastPressEnterOrEscape;

    public AutoFilterProjectsComboboxListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, JComboBox cbProjects) {
        this.cbProjects = cbProjects;
        this.cbTextField = (JTextField) this.cbProjects.getEditor().getEditorComponent();
        this.autoFilterComboboxModel = (AutoFilterProjectsComboboxModel) this.cbProjects.getModel();
        lastFilter = "";
    }

    @Override
    public void keyTyped(KeyEvent e) {
        SwingUtilities.invokeLater(() -> {
            String pattern = cbTextField.getText();

            if (lastFilter != null && !lastFilter.equals(pattern)) {
                lastFilter = pattern;

                autoFilterComboboxModel.filterList(pattern, !lastPressDeleteOrBackspace);

                if (autoFilterComboboxModel.getSize() != 1 || (autoFilterComboboxModel.getSize() == 1 && lastPressDeleteOrBackspace)) {
                    cbTextField.setText(pattern);
                    cbTextField.setCaretPosition(pattern.length());
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
        // no-op
    }

    private void markDifferenceBetweenPattern(String pattern) {
        if (lastPressDeleteOrBackspace) {
            markText(cbTextField.getText().length());
        } else {
            markText(pattern.length());
        }
    }

    private void markText(int start) {
        try {
            cbTextField.setCaretPosition(cbTextField.getText().length());
            cbTextField.moveCaretPosition(start);
        } catch (IllegalArgumentException ignored) {
        }
    }

    private synchronized void hideAndShowPopup() {
        if (cbProjects.isPopupVisible()) {
            cbProjects.hidePopup();
        }
        if (!lastPressEnterOrEscape) {
            cbProjects.showPopup();
        }
    }
}
