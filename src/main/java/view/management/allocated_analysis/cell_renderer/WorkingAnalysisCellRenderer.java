package view.management.allocated_analysis.cell_renderer;

import models.analysis.Analysis;
import services.AnalysisService;
import utilities.Util;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class WorkingAnalysisCellRenderer extends DefaultTableCellRenderer {

    private AnalysisService analysisService;
    private Color defaultForegroundColor;

    public WorkingAnalysisCellRenderer(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        this.setHorizontalAlignment(JLabel.CENTER);
        Analysis workingAnalysis = analysisService.getWorkingAnalysis();

        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if(workingAnalysis != null){
            int projectId = (int) table.getValueAt(row, 0);
            if(projectId == workingAnalysis.getId()){
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
