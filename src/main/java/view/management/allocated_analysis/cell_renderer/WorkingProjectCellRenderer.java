package view.management.allocated_analysis.cell_renderer;

import models.project.Project;
import services.ProjectService;
import utilities.Util;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class WorkingProjectCellRenderer extends DefaultTableCellRenderer {

    private ProjectService projectService;
    private Color defaultForegroundColor;

    public WorkingProjectCellRenderer(ProjectService projectService) {
        this.projectService = projectService;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        this.setHorizontalAlignment(JLabel.CENTER);
        Project workingProject = projectService.getWorkingProject();

        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if(workingProject != null){
            int projectId = (int) table.getValueAt(row, 0);
            if(projectId == workingProject.getId()){
                component.setForeground(this.getHighlightColor());
            }else{
                component.setForeground(table.getForeground());
            }
        }else{
            component.setForeground(table.getForeground());
        }
        return component;
    }

    public Color getHighlightColor(){
        if(Util.isColorDark(this.getBackground())) {
            return new Color(225, 107, 46);
        }else{
            return Color.BLUE;
        }
    }

    public Color getDefaultForegroundColor() {
        return defaultForegroundColor;
    }



    public void setDefaultForegroundColor(Color defaultForegroundColor) {
        this.defaultForegroundColor = defaultForegroundColor;
    }

}
