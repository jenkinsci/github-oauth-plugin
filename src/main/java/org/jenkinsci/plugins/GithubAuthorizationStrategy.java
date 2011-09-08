/**
 * 
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

		/**
	 * 
	 */
	@DataBoundConstructor
	public GithubAuthorizationStrategy(String adminUserNames,
			boolean authenticatedUserReadPermission, String organizationNames, boolean allowGithubWebHookPermission) {
		super();

		rootACL = new GithubRequireOrganizationMembershipACL(adminUserNames,
				organizationNames, authenticatedUserReadPermission, allowGithubWebHookPermission);
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
		return StringUtils.join(rootACL.getOrganizationNameList(), ",");
	}



	/**
	 * @return
	 * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#getAdminUserNameList()
	 */
	public String getAdminUserNames() {
		return StringUtils.join(rootACL.getAdminUserNameList(), ",");
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
