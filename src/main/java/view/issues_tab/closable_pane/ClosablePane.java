package view.issues_tab.closable_pane;

import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class ClosablePane extends JPanel {

    private final JPanel rootPanel;
    private final JLabel txtTitle;
    private final JButton btnCloseTab;
    private Boolean isDarkBackground = false;

    public ClosablePane(String titleText) {
        rootPanel = this;
        rootPanel.setLayout(new FormLayout("fill:min(d;30px):noGrow,left:3px:noGrow,fill:12px:noGrow", "center:d:grow"));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new FormLayout("fill:62px:grow,fill:min(d;10px):noGrow", "center:d:grow"));
        CellConstraints cc = new CellConstraints();
        rootPanel.add(panel1, cc.xy(1, 1, CellConstraints.DEFAULT, CellConstraints.FILL));
        txtTitle = new JLabel();
        txtTitle.setText(titleText);
        panel1.add(txtTitle, cc.xyw(1, 1, 2));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new FormLayout("fill:12px:noGrow", "center:d:grow"));
        rootPanel.add(panel2, cc.xy(3, 1, CellConstraints.DEFAULT, CellConstraints.FILL));
        btnCloseTab = new JButton();
        btnCloseTab.setBorderPainted(false);
        btnCloseTab.setFocusable(false);
        btnCloseTab.setIcon(new ImageIcon(getClass().getResource("/icons/cancel-lightbkg.png")));
        btnCloseTab.setText("");
        panel2.add(btnCloseTab, cc.xy(1, 1, CellConstraints.DEFAULT, CellConstraints.CENTER));

        btnCloseTab.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                ClosablePane clickedPane = (ClosablePane) ((JButton) e.getSource()).getParent().getParent();
                JTabbedPane fathersPane = (JTabbedPane) clickedPane.getParent().getParent();
                int indexToRemove = -1;
                for (int i = 0; i < fathersPane.getTabCount(); i++) {
                    if (fathersPane.getTabComponentAt(i) instanceof ClosablePane) {
                        ClosablePane auxPane = (ClosablePane) fathersPane.getTabComponentAt(i);
                        if (auxPane.getTabTitle().equals(clickedPane.getTabTitle())) {
                            indexToRemove = i;
                            break;
                        }
                    }
                }
                if (indexToRemove > 0) {
                    fathersPane.setSelectedIndex(indexToRemove - 1);
                    fathersPane.remove(indexToRemove);
                } else {
                    fathersPane.setSelectedIndex(1);
                    fathersPane.remove(0);
                }

            }
        });

        if(this.isColorDark(rootPanel.getBackground())){
            this.isDarkBackground = true;
            this.setBtnCloseTabToDarkBkg();
        }

        this.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals("foreground")) {
                if (!this.isDarkBackground) {
                    this.isDarkBackground = true;
                    this.setBtnCloseTabToDarkBkg();

                } else {
                    this.isDarkBackground = false;
                    this.setBtnCloseTabToLightBkg();
                }
            }
        });
    }

    public String getTabTitle() {
        return this.txtTitle.getText();
    }

    private void setBtnCloseTabToDarkBkg(){
        btnCloseTab.setContentAreaFilled(false);
        btnCloseTab.setIcon(new ImageIcon(getClass().getResource("/icons/cancel-darkbkg.png")));
        btnCloseTab.setBackground(this.rootPanel.getBackground());
    }

    private void setBtnCloseTabToLightBkg(){
        btnCloseTab.setContentAreaFilled(true);
        btnCloseTab.setIcon(new ImageIcon(getClass().getResource("/icons/cancel-lightbkg.png")));
    }

    public boolean isColorDark(Color color){
        double darkness = 1-((0.299* color.getRed()) + (0.587*color.getGreen())+ (0.114*color.getBlue()))/255;
        return !(darkness < 0.5); // It's a light color
    }
}
