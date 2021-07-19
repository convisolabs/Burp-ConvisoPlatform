package models.evidences;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.File;
import java.util.Arrays;
import java.util.List;

public class EvidenceFileChooser extends JFileChooser {

    public static final List<String> acceptedExtensions = Arrays.asList(".pdf", ".zip", ".jpg", ".jpeg", ".png", ".txt", ".doc", ".xls", ".rar", ".docx", ".gif");

    public EvidenceFileChooser() {
        this.setFileFilter(new FileNameExtensionFilter(String.join(", ", acceptedExtensions), "pdf", "zip", "jpg", "jpeg", "png", "txt", "doc", "xls", "rar", "docx", "gif"));
    }

    public EvidenceFileChooser(String currentDirectoryPath) {
        super(currentDirectoryPath);
        this.setFileFilter(new FileNameExtensionFilter(String.join(", ", acceptedExtensions), "pdf", "zip", "jpg", "jpeg", "png", "txt", "doc", "xls", "rar", "docx", "gif"));
    }

    public EvidenceFileChooser(File currentDirectory) {
        super(currentDirectory);
        this.setFileFilter(new FileNameExtensionFilter(String.join(", ", acceptedExtensions), "pdf", "zip", "jpg", "jpeg", "png", "txt", "doc", "xls", "rar", "docx", "gif"));
    }
}
