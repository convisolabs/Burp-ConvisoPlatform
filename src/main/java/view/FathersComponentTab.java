package view;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import models.services_manager.ServicesManager;
import models.tabs_manager.TabsManager;
import utilities.Util;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import javax.swing.text.StyleContext;
import java.awt.*;
import java.util.Locale;

public abstract class FathersComponentTab extends DefaultView{

    protected Color defaultLblColor;
    protected Color defaultBackgroundBtn;
    protected Color defaultForegroundBtn;
    protected boolean isDarkBackground = false;

    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;
    protected Util util;
    protected Component rootObject;
    protected final ServicesManager servicesManager;
    protected TabsManager tabsManager = null;

    public FathersComponentTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
        this.servicesManager = servicesManager;
    }

    public FathersComponentTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager, TabsManager tabsManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
        this.servicesManager = servicesManager;
        this.tabsManager = tabsManager;
    }

    protected void setDefaultColors(JLabel jLabel) {
        this.defaultLblColor = jLabel.getForeground();
    }

    protected void setDefaultColors(JButton jButton) {
        this.defaultForegroundBtn = jButton.getForeground();
        this.defaultBackgroundBtn = jButton.getBackground();
    }

    private void setDarkBackgroundChecker(Component component) {
        this.isDarkBackground = Util.isColorDark(component.getBackground());
    }

    private void addChangeColorEventListener(Component component) {
        component.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals("foreground")) {
                this.defaultLblColor = (Color) evt.getNewValue();
                this.defaultBackgroundBtn = component.getBackground();
                this.defaultForegroundBtn = component.getForeground();
                this.isDarkBackground = Util.isColorDark(component.getBackground());
            }
        });
    }

    public void setRootPanel(Component rootPanel) {
        this.rootObject = rootPanel;
        this.setDarkBackgroundChecker(this.rootObject);
        this.addChangeColorEventListener(this.rootObject);
    }

    protected void addLblBoldListener(Component component){
        component.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals("foreground")) {
                Font fontLblBold = $$$getFont$$$(null, Font.BOLD, -1, component.getFont());
                if (fontLblBold != null) ((JLabel) evt.getSource()).setFont(fontLblBold);
            }
        });

    }


    /**
     * @noinspection ALL
     */
    private Font $$$getFont$$$(String fontName, int style, int size, Font currentFont) {
        if (currentFont == null) return null;
        String resultName;
        if (fontName == null) {
            resultName = currentFont.getName();
        } else {
            Font testFont = new Font(fontName, Font.PLAIN, 10);
            if (testFont.canDisplay('a') && testFont.canDisplay('1')) {
                resultName = fontName;
            } else {
                resultName = currentFont.getName();
            }
        }
        Font font = new Font(resultName, style >= 0 ? style : currentFont.getStyle(), size >= 0 ? size : currentFont.getSize());
        boolean isMac = System.getProperty("os.name", "").toLowerCase(Locale.ENGLISH).startsWith("mac");
        Font fontWithFallback = isMac ? new Font(font.getFamily(), font.getStyle(), font.getSize()) : new StyleContext().getFont(font.getFamily(), font.getStyle(), font.getSize());
        return fontWithFallback instanceof FontUIResource ? fontWithFallback : new FontUIResource(fontWithFallback);
    }
}
