package services;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import models.project.Project;
import utilities.Util;

public class ProjectService {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private Project[] allAlocatedProjects;
    private final Util util;

    public ProjectService(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.util = new Util(this.callbacks, this.helpers);
    }




}
