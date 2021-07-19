package view.issues_tab.popup_menu;

import models.evidences.EvidenceArchive;
import models.evidences.EvidenceFileChooser;
import utilities.Util;
import view.issues_tab.NewIssueTab;

import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.io.File;
import java.util.prefs.Preferences;

public class EvidencePopupMenu extends JPopupMenu {
    JMenuItem addEvidence;
    JMenuItem addTextEvidence;
    JMenuItem removeEvidence;
    Util util;
    NewIssueTab newIssueTab;
    Preferences prefs = Preferences.userRoot().node(getClass().getName());
    static final String LAST_USED_FOLDER = "LAST_USED_FOLDER";


    public EvidencePopupMenu(NewIssueTab newIssueTab){//DefaultListModel<Evidence> evidenceListModel, JList evidenceList){
        this.newIssueTab = newIssueTab;
        this.util = new Util();

        addEvidence = new JMenuItem("Add file");

        addEvidence.addActionListener(e -> new Thread(() -> {
            EvidenceFileChooser evidenceFileChooser = new EvidenceFileChooser(prefs.get(LAST_USED_FOLDER, new File(String.valueOf(FileSystemView.getFileSystemView().getDefaultDirectory())).getAbsolutePath()));
            int returnValue = evidenceFileChooser.showOpenDialog(this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = evidenceFileChooser.getSelectedFile();
                prefs.put(LAST_USED_FOLDER, evidenceFileChooser.getSelectedFile().getParent());
                this.newIssueTab.addEvidence(new EvidenceArchive(selectedFile.getAbsolutePath(), selectedFile.getName()));
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

            JOptionPane.showMessageDialog(newIssueTab.getRootPanel2(), new JScrollPane(jTextArea), "Evidence content", JOptionPane.PLAIN_MESSAGE);
            UIManager.put("OptionPane.minimumSize", defaultDimension);

            String content = jTextArea.getText();
            if(!content.isEmpty()){
                File textEvidence = util.createTempFile("evidence-uid-", content);
                newIssueTab.addEvidence(new EvidenceArchive(textEvidence.getAbsolutePath(), textEvidence.getName()));
            }
        });

        removeEvidence = new JMenuItem("Remove");

        removeEvidence.addActionListener(e -> new Thread(() -> {
            this.newIssueTab.removeSelectedEvidence();
        }).start());

        add(addEvidence);
        add(addTextEvidence);
        add(removeEvidence);


    }

}
