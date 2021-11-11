package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import models.services_manager.ServicesManager;
import utilities.Util;

import java.util.Calendar;

public class Service {

    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;
    protected Util util;
    protected boolean alreadyLoaded;
    protected Calendar lastRequestTime;
    protected ServicesManager servicesManager;

    public Service(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
        this.servicesManager = servicesManager;
    }

    public void setLastRequest() {
        this.lastRequestTime = Calendar.getInstance();
    }
}
