package view.management.allocated_projects.cell_renderer;

import models.project.Project;
import services.ProjectService;
import utilities.Util;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class WorkingProjectCellRenderer extends DefaultTableCellRenderer {

    private ProjectService projectService;
    private Color defaultForegroundColor;
    private Color defaultBackgroundColor;

    public WorkingProjectCellRenderer(ProjectService projectService) {
        this.projectService = projectService;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        System.out.println("notevenhere");
        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        this.setHorizontalAlignment(JLabel.CENTER);
        Project workingProject = projectService.getWorkingProject();
        if(workingProject != null && column == 0 && String.valueOf(value).equals(String.valueOf(workingProject.getId()))){
//            if(Util.isColorDark(component.getBackground())) {
                component.setForeground(new Color(225, 107, 46));
//            }
//            }else{
//                component.setBackground(new Color(225, 107, 46));
//            }

        }else{
//            if(Util.isColorDark(component.getBackground())){
                component.setForeground(defaultForegroundColor);
//            }

//            }else{
//                component.setBackground(defaultBackgroundColor);
//            }
        }
        return component;
    }


    public Color getDefaultForegroundColor() {
        return defaultForegroundColor;
    }

    public void setDefaultForegroundColor(Color defaultForegroundColor) {
        this.defaultForegroundColor = defaultForegroundColor;
    }

    public Color getDefaultBackgroundColor() {
        return defaultBackgroundColor;
    }

    public void setDefaultBackgroundColor(Color defaultBackgroundColor) {
        this.defaultBackgroundColor = defaultBackgroundColor;
    }
}
