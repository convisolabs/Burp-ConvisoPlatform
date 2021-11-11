package view;

import utilities.Util;

import javax.swing.*;
import java.awt.*;

public abstract class DefaultView {

    protected void setLblRequired(JLabel[] jLabels, JComponent toCompare) {
        for (JLabel label :
                jLabels) {
            label.setText(label.getText() + "*");
            if (Util.isColorDark(toCompare.getBackground())) {
                label.setForeground(new Color(225, 107, 46));
            } else {
                label.setForeground(Color.RED);
            }
        }
    }

    protected void setLblDefault(JLabel[] jLabels, JComponent toCompare) {
        for (JLabel label :
                jLabels) {
            label.setText(label.getText().replace("*", ""));
            label.setForeground(toCompare.getForeground());
        }
    }
}
