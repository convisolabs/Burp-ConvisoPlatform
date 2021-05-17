package view;

import utilities.Util;

import javax.swing.*;
import java.awt.*;

public abstract class FathersTab {

    protected Color defaultLblColor;
    protected boolean isDarkBackground = false;
    protected Util util;

    protected void setDefaultLblColor(JLabel jLabel){
        this.defaultLblColor = jLabel.getForeground();
    }

    protected void setDarkBackground(Component component){
        this.util.isColorDark(component.getBackground());
    }

    protected void addChangeColorEventListener(Component component){
        component.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals("foreground")) {
                this.defaultLblColor = (Color) evt.getNewValue();
                this.isDarkBackground = this.util.isColorDark(component.getBackground());
            }
        });
    }

}
