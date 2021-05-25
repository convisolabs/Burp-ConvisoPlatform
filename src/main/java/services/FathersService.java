package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import models.services_manager.ServicesManager;
import utilities.Util;

import java.util.Calendar;

public class FathersService {

    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;
    protected Util util;
    protected boolean alreadyLoaded;
    protected Calendar lastRequestTime;
    protected ServicesManager servicesManager;

    public FathersService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, ServicesManager servicesManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
        this.servicesManager = servicesManager;
    }
}
