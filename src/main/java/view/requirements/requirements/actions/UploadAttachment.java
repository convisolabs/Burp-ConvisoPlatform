package view.requirements.requirements.actions;

import com.google.gson.JsonSyntaxException;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;
import models.attachments.AttachmentFileChooser;
import models.services_manager.ServicesManager;
import models.attachments.AttachmentArchive;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpResponseException;
import services.ActivityService;
import utilities.Util;
import view.DefaultView;
import view.requirements.requirements.RequirementsTab;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;
import javax.swing.plaf.FontUIResource;
import javax.swing.text.StyleContext;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.prefs.Preferences;
import java.util.stream.Collectors;

public class UploadAttachment extends DefaultView {
    private JPanel rootPanel;
    private JTextArea txtAreaEvidence;
    private JButton selectedArchiveButton;
    private JLabel lblEvidencePath;
    private JButton btnSubmit;
    private JLabel lblEvidence;
    private JLabel lblArchive;
    private JLabel lblAcceptedExtensions;
    Preferences prefs = Preferences.userRoot().node(getClass().getName());
    static final String LAST_USED_FOLDER_FOR_ATTACHMENT = "LAST_USED_FOLDER_FOR_ATTACHMENT";
    final ServicesManager servicesManager;
    private AttachmentArchive attachmentArchiveOfActivity;


    public UploadAttachment(ServicesManager servicesManager, RequirementsTab requirementsTab, Util util) {
        this.servicesManager = servicesManager;
        this.lblAcceptedExtensions.setText("Accepted extensions: " + String.join(", ", AttachmentFileChooser.acceptedExtensions));

        selectedArchiveButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                AttachmentFileChooser attachmentFileChooser = new AttachmentFileChooser(prefs.get(LAST_USED_FOLDER_FOR_ATTACHMENT, new File(String.valueOf(FileSystemView.getFileSystemView().getDefaultDirectory())).getAbsolutePath()));
                int returnValue = attachmentFileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = attachmentFileChooser.getSelectedFile();
                    prefs.put(LAST_USED_FOLDER_FOR_ATTACHMENT, attachmentFileChooser.getSelectedFile().getParent());
                    attachmentArchiveOfActivity = new AttachmentArchive(selectedFile.getAbsolutePath(), selectedFile.getName());
                    if (attachmentArchiveOfActivity.validateExtension()) {
                        setLblDefault(new JLabel[]{lblEvidencePath, lblArchive}, rootPanel);
                        lblEvidencePath.setText("Selected attachment: " + selectedFile.getAbsolutePath());
                    } else {
                        attachmentArchiveOfActivity = null;
                        lblEvidencePath.setText("Not accepted extension!");
                        setLblRequired(new JLabel[]{lblEvidencePath, lblArchive}, rootPanel);
                    }
                }
            }
        });

        btnSubmit.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                new Thread(() -> {
                    if (!btnSubmit.isEnabled()) {
                        return;
                    }
                    btnSubmit.setEnabled(false);

                    String textEvidence = txtAreaEvidence.getText();

                    if (attachmentArchiveOfActivity != null || !textEvidence.isEmpty()) {
                        JTable jTable = requirementsTab.getTblInProgressRequirements();
                        ActivityService activityService = servicesManager.getActivityService();

                        List<Integer> indexes = Arrays.stream(jTable.getSelectedRows()).boxed().collect(Collectors.toList());
                        Collections.reverse(indexes);

                        if (indexes.isEmpty()) {
                            JOptionPane.showMessageDialog(rootPanel, "Please select at least one requirement.");
                            btnSubmit.setEnabled(true);
                            return;
                        }

                        for (int i :
                                indexes) {
                            try {
                                activityService.updateActivityToFinish((Integer) jTable.getValueAt(i, 0), attachmentArchiveOfActivity, textEvidence);
                                SwingUtilities.getWindowAncestor(rootPanel).setVisible(false);
                                requirementsTab.refreshRequirementsAsync();
                            } catch (Error | JsonSyntaxException | HttpResponseException | FileNotFoundException err) {
                                util.sendStderr(err.toString());
                                JOptionPane.showMessageDialog(rootPanel, "Error!\nCheck the errors in extender tab!");
                            } catch (AuthenticationException authenticationException) {
                                util.sendStderr(authenticationException.toString());
                                JOptionPane.showMessageDialog(rootPanel, "Error!\nAuthentication exception!\nCheck the errors in extender tab!");
                            }
                        }


                        lblEvidence.setText("Attachment");
                        lblArchive.setText("Attachment");
                        setLblDefault(new JLabel[]{lblEvidence, lblArchive}, rootPanel);
                    } else {
                        lblEvidence.setText("Attachment*");
                        lblArchive.setText("Attachment*");
                        setLblRequired(new JLabel[]{lblEvidence, lblArchive}, rootPanel);
                    }

                    btnSubmit.setEnabled(true);

                }).start();
            }
        });
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
        rootPanel = new JPanel();
        rootPanel.setLayout(new FormLayout("fill:300px:grow", "center:60dlu:noGrow,top:4dlu:noGrow,center:max(p;5dlu):noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:20dlu:noGrow,center:max(d;4px):noGrow"));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new FormLayout("fill:d:grow", "fill:10dlu:noGrow,top:4dlu:noGrow,fill:d:grow"));
        CellConstraints cc = new CellConstraints();
        rootPanel.add(panel1, cc.xy(1, 1, CellConstraints.DEFAULT, CellConstraints.FILL));
        lblEvidence = new JLabel();
        Font lblEvidenceFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblEvidence.getFont());
        if (lblEvidenceFont != null) lblEvidence.setFont(lblEvidenceFont);
        lblEvidence.setText("Attachment");
        panel1.add(lblEvidence, cc.xy(1, 1));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new FormLayout("fill:d:grow", "center:d:grow"));
        panel1.add(panel2, cc.xy(1, 3, CellConstraints.FILL, CellConstraints.FILL));
        panel2.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(new Color(-4473925)), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        txtAreaEvidence = new JTextArea();
        txtAreaEvidence.setLineWrap(true);
        panel2.add(txtAreaEvidence, cc.xy(1, 1, CellConstraints.FILL, CellConstraints.FILL));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new FormLayout("fill:d:grow", "center:max(d;4px):noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow,top:4dlu:noGrow,center:max(d;4px):noGrow"));
        rootPanel.add(panel3, cc.xy(1, 5));
        lblArchive = new JLabel();
        Font lblArchiveFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblArchive.getFont());
        if (lblArchiveFont != null) lblArchive.setFont(lblArchiveFont);
        lblArchive.setText("Attachment");
        panel3.add(lblArchive, cc.xy(1, 1));
        lblAcceptedExtensions = new JLabel();
        lblAcceptedExtensions.setText("");
        panel3.add(lblAcceptedExtensions, cc.xy(1, 3));
        selectedArchiveButton = new JButton();
        selectedArchiveButton.setText("Select attachment");
        panel3.add(selectedArchiveButton, cc.xy(1, 7));
        lblEvidencePath = new JLabel();
        Font lblEvidencePathFont = this.$$$getFont$$$(null, Font.BOLD, -1, lblEvidencePath.getFont());
        if (lblEvidencePathFont != null) lblEvidencePath.setFont(lblEvidencePathFont);
        lblEvidencePath.setText("");
        panel3.add(lblEvidencePath, cc.xy(1, 5));
        final JSeparator separator1 = new JSeparator();
        rootPanel.add(separator1, cc.xy(1, 3, CellConstraints.FILL, CellConstraints.FILL));
        btnSubmit = new JButton();
        btnSubmit.setBackground(new Color(-14260834));
        btnSubmit.setForeground(new Color(-1));
        btnSubmit.setText("Submit");
        rootPanel.add(btnSubmit, cc.xy(1, 7, CellConstraints.CENTER, CellConstraints.DEFAULT));
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

    private void createUIComponents() {
    }
}
