package view.vulnerabilities_tab.listeners;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import models.auto_filter_combobox.AutoFilterAssetsComboboxModel;

import javax.swing.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

public class AutoFilterAssetsComboboxListener implements KeyListener {

    private final JComboBox cbAssets;
    private final JTextField cbTextField;
    private final AutoFilterAssetsComboboxModel autoFilterComboboxModel;
    private String lastFilter;
    private static boolean lastPressDeleteOrBackspace;
    private static boolean lastPressEnterOrEscape;

    public AutoFilterAssetsComboboxListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, JComboBox cbAssets) {
        this.cbAssets = cbAssets;
        this.cbTextField = (JTextField) this.cbAssets.getEditor().getEditorComponent();
        this.autoFilterComboboxModel = (AutoFilterAssetsComboboxModel) this.cbAssets.getModel();
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
        if (cbAssets.isPopupVisible()) {
            cbAssets.hidePopup();
        }
        if (!lastPressEnterOrEscape) {
            cbAssets.showPopup();
        }
    }
}
