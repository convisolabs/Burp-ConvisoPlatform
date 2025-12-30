package models.auto_filter_combobox;

import models.project.Project;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class AutoFilterProjectsComboboxModel extends DefaultComboBoxModel {

    private List<Project> projectsList;

    public AutoFilterProjectsComboboxModel() {
        this.projectsList = new ArrayList<>();
    }

    public void setProjectsList(List<Project> projectsList) {
        if (!projectsList.isEmpty()) {
            this.projectsList = projectsList;
            this.removeAllElements();
            this.addAll(projectsList);
        }
    }

    public synchronized void filterList(String pattern, boolean setSoloElement) {
        List<Project> filteredList = new ArrayList<>();

        if (pattern != null && !pattern.isEmpty()) {
            String loweredPattern = pattern.toLowerCase();
            for (Project p : projectsList) {
                String label = p.toString();
                if (label.toLowerCase().contains(loweredPattern)) {
                    filteredList.add(p);
                }
            }
            this.removeAllElements();
            this.addAll(filteredList);
            if (filteredList.size() == 1 && setSoloElement) {
                this.setSelectedItem(filteredList.get(0));
            }
        } else {
            this.removeAllElements();
            this.addAll(projectsList);
        }
    }
}
