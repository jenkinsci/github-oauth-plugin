/**
 The MIT License

Copyright (c) 2011 Michael O'Cleirigh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.



 */
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.Util;
import hudson.model.Item;
import hudson.model.AbstractProject;
import hudson.model.BuildAuthorizationToken;
import hudson.model.Descriptor;
import hudson.model.Job;
import hudson.model.Node;
import hudson.model.Project;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import jenkins.model.Jenkins;

import org.acegisecurity.Authentication;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.URIUtil;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Stapler;

/**
 * @author mocleiri
 * 
 * 
 * 
 */
public class GithubAuthorizationStrategy extends AuthorizationStrategy {
    @Deprecated
    public GithubAuthorizationStrategy(String adminUserNames,
    			    boolean authenticatedUserReadPermission, boolean useRepositoryPermissions,
                    String organizationNames,
    			    boolean allowGithubWebHookPermission, boolean allowCcTrayPermission,
    			    boolean allowAnonymousReadPermission, boolean allowAnonymousJobStatusPermission) {
    		this(adminUserNames, authenticatedUserReadPermission, useRepositoryPermissions, false, organizationNames, allowGithubWebHookPermission, allowCcTrayPermission, allowAnonymousReadPermission, allowAnonymousJobStatusPermission);
    }

	/**
	 * @param allowAnonymousReadPermission
	 * @since 0.19
	 */
	@DataBoundConstructor
	public GithubAuthorizationStrategy(String adminUserNames,
			boolean authenticatedUserReadPermission, boolean useRepositoryPermissions,
                        boolean authenticatedUserCreateJobPermission, String organizationNames,
			boolean allowGithubWebHookPermission, boolean allowCcTrayPermission,
			boolean allowAnonymousReadPermission, boolean allowAnonymousJobStatusPermission) {
		super();

		rootACL = new GithubRequireOrganizationMembershipACL(adminUserNames,
				organizationNames, authenticatedUserReadPermission,
                                useRepositoryPermissions, authenticatedUserCreateJobPermission,
                                allowGithubWebHookPermission,
                                allowCcTrayPermission, allowAnonymousReadPermission,
                                allowAnonymousJobStatusPermission);
	}

	private final GithubRequireOrganizationMembershipACL rootACL;

	/*
	 * (non-Javadoc)
	 * 
	 * @see hudson.security.AuthorizationStrategy#getRootACL()
	 */
	@Override
	public ACL getRootACL() {

		return rootACL;

	}

	public ACL getACL(Job<?,?> job) {
		if(job instanceof AbstractProject) {
			AbstractProject project = (AbstractProject)job;
	                GithubRequireOrganizationMembershipACL githubACL = (GithubRequireOrganizationMembershipACL) getRootACL();
			return githubACL.cloneForProject(project);
		  } else {
			return getRootACL();
		  }
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see hudson.security.AuthorizationStrategy#getGroups()
	 */
	@Override
	public Collection<String> getGroups() {
		return new ArrayList<String>(0);
	}

	private Object readResolve() {
		return this;
	}

	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#getOrganizationNameList()
	 */
	public String getOrganizationNames() {
		return StringUtils.join(rootACL.getOrganizationNameList().iterator(), ", ");
	}

	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#getAdminUserNameList()
	 */
	public String getAdminUserNames() {
		return StringUtils.join(rootACL.getAdminUserNameList().iterator(), ", ");
	}

	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isUseRepositoryPermissions()
	 */
	public boolean isUseRepositoryPermissions() {
		return rootACL.isUseRepositoryPermissions();
	}

	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAuthenticatedUserCreateJobPermission()
	 */
	public boolean isAuthenticatedUserCreateJobPermission() {
		return rootACL.isAuthenticatedUserCreateJobPermission();
	}

	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAuthenticatedUserReadPermission()
	 */
	public boolean isAuthenticatedUserReadPermission() {
		return rootACL.isAuthenticatedUserReadPermission();
	}

	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAllowGithubWebHookPermission()
	 */
	public boolean isAllowGithubWebHookPermission() {
		return rootACL.isAllowGithubWebHookPermission();
	}

	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAllowCcTrayPermission()
	 */
	public boolean isAllowCcTrayPermission() {
		return rootACL.isAllowCcTrayPermission();
	}

	
	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAllowAnonymousReadPermission()
	 */
	public boolean isAllowAnonymousReadPermission() {
		return rootACL.isAllowAnonymousReadPermission();
	}

	/**
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAllowAnonymousJobStatusPermission()
	 * @return
	 */
	public boolean isAllowAnonymousJobStatusPermission() {
		return rootACL.isAllowAnonymousJobStatusPermission();
	}

	@Extension
	public static final class DescriptorImpl extends
			Descriptor<AuthorizationStrategy> {

		public String getDisplayName() {
			return "Github Commiter Authorization Strategy";
		}

		public String getHelpFile() {
			return "/plugin/github-oauth/help/help-authorization-strategy.html";
		}
	}
}
