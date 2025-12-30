package view.vulnerabilities_tab.popup_menu;

import models.attachments.AttachmentArchive;
import models.attachments.AttachmentFileChooser;
import utilities.Util;
import view.vulnerabilities_tab.NewVulnerabilityTab;

import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.io.File;
import java.util.prefs.Preferences;

public class AttachmentPopupMenu extends JPopupMenu {
    JMenuItem addEvidence;
    JMenuItem addTextEvidence;
    JMenuItem removeEvidence;
    Util util;
    NewVulnerabilityTab newVulnerabilityTab;
    Preferences prefs = Preferences.userRoot().node(getClass().getName());
    static final String LAST_USED_FOLDER = "LAST_USED_FOLDER";


    public AttachmentPopupMenu(NewVulnerabilityTab newVulnerabilityTab){
        this.newVulnerabilityTab = newVulnerabilityTab;
        this.util = new Util();

        addEvidence = new JMenuItem("Add attachment");

        addEvidence.addActionListener(e -> new Thread(() -> {
            AttachmentFileChooser evidenceFileChooser = new AttachmentFileChooser(prefs.get(LAST_USED_FOLDER, new File(String.valueOf(FileSystemView.getFileSystemView().getDefaultDirectory())).getAbsolutePath()));
            int returnValue = evidenceFileChooser.showOpenDialog(this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = evidenceFileChooser.getSelectedFile();
                prefs.put(LAST_USED_FOLDER, evidenceFileChooser.getSelectedFile().getParent());
                this.newVulnerabilityTab.addEvidence(new AttachmentArchive(selectedFile.getAbsolutePath(), selectedFile.getName()));
            }
        }).start());

        addTextEvidence = new JMenuItem("Add text");

        addTextEvidence.addActionListener(e -> {
            Dimension defaultDimension = (Dimension) UIManager.get("OptionPane.minimumSize");
            UIManager.put("OptionPane.minimumSize",new Dimension(250,250));

            JTextArea jTextArea = new JTextArea();
            jTextArea.setColumns(30);
            jTextArea.setLineWrap(true);
            jTextArea.setWrapStyleWord(true);
            jTextArea.setSize(jTextArea.getPreferredSize().width, jTextArea.getPreferredSize().height);

            JOptionPane.showMessageDialog(newVulnerabilityTab.getRootPanel2(), new JScrollPane(jTextArea), "Attachment content", JOptionPane.PLAIN_MESSAGE);
            UIManager.put("OptionPane.minimumSize", defaultDimension);

            String content = jTextArea.getText();
            if(!content.isEmpty()){
                File textEvidence = util.createTempFile("attachment-uid-", content);
                newVulnerabilityTab.addEvidence(new AttachmentArchive(textEvidence.getAbsolutePath(), textEvidence.getName()));
            }
        });

        removeEvidence = new JMenuItem("Remove");

        removeEvidence.addActionListener(e -> new Thread(() -> {
            this.newVulnerabilityTab.removeSelectedEvidence();
        }).start());

        add(addEvidence);
        add(addTextEvidence);
        add(removeEvidence);


    }

}
