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

	private static final String ORGANIZATION_NAMES = "organizationNames";
	private static final String AUTHENTICATED_USER_READ_PERMISSION = "authenticatedUserReadPermission";
	private static final String ADMIN_USER_NAMES = "adminUserNames";

	private static class GithubRequireOrganizationMembershipACL extends ACL {

		private final List<String> organizationNameList;
		private final List<String> adminUserNameList;
		private final boolean authenticatedUserReadPermission;

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * hudson.security.ACL#hasPermission(org.acegisecurity.Authentication,
		 * hudson.security.Permission)
		 */
		@Override
		public boolean hasPermission(Authentication a, Permission permission) {

			if (a != null && a instanceof GithubAuthenticationToken) {

				GithubAuthenticationToken authenticationToken = (GithubAuthenticationToken) a;

				String candidateName = a.getName();

				if (adminUserNameList.contains(candidateName))
					// if they are an admin then they have permission
					return true;

				if (authenticatedUserReadPermission) {

					String[] parts = permission.getId().split("\\.");
					if (parts[parts.length - 1].toLowerCase().equals("read"))

						// if we support authenticated read and this is a read
						// request we allow it
						return true;
				}

				for (String organizationName : this.organizationNameList) {

					if (authenticationToken.hasOrganizationPermission(
							candidateName, organizationName)) {

						String[] parts = permission.getId().split("\\.");

						String test = parts[parts.length - 1].toLowerCase();

						if (test.equals("read") || test.equals("build"))
							// check the permission
							return true;
					}

				}

				// no match.
				return false;

			} else {

				String p = a.getName();

				if (p.equals(SYSTEM.getPrincipal())) {
					// give system user full access
					return true;
				}

				if (a.getName().equals("anonymous")) {
					// deny anonymous users
					// everyone must be logged in
					String requestURI = Stapler.getCurrentRequest()
							.getOriginalRequestURI();

					if (requestURI.matches("^.*\\/job\\/.*/build$")) {

						/*
						 * pull out the job name then look up the authentication
						 * token and test it
						 */

						String parts[] = requestURI.split("/");

						boolean started = false;

						String projectName = null;

						for (String part : parts) {

							if (part.equals("job")) {
								started = true;
								continue;
							}

							if (started) {
								try {
									projectName =  URIUtil.decode(part);
								} catch (URIException e) {
									// should log here.
									return false;
								}
								break;
							}

						}

						String authorizedBuildToken = null;

						if (projectName != null) {

//							 Item item = Jenkins.getInstance().getItemByFullName(projectName);
							
							Item item = null;
							
							
								if (item != null && item instanceof AbstractProject) {
									
										AbstractProject ap = (AbstractProject) item;
										
										BuildAuthorizationToken buildToken = ap
												.getAuthToken();

										authorizedBuildToken = buildToken
												.getToken();
								}

							String buildToken = (String) Stapler
									.getCurrentRequest().getParameter("token");

							// ensure they have a valid build token

							if (permission.getId().equals(
									"hudson.model.Hudson.Read")
									|| permission.getId().equals(
											"hudson.model.Item.Read")
									&& authorizedBuildToken != null
									&& authorizedBuildToken.equals(buildToken))
								return true;

						}

						// else fall through to false.
					}
					return false;
				}

				if (adminUserNameList.contains(p)) {
					// if they are an admin then they have all permissions
					return true;
				}

				return false;

			}

		}

		public GithubRequireOrganizationMembershipACL(String adminUserNames,
				String organizationNames,
				boolean authenticatedUserReadPermission) {
			super();
			this.authenticatedUserReadPermission = authenticatedUserReadPermission;

			this.adminUserNameList = new LinkedList<String>();

			String[] parts = adminUserNames.split(",");

			for (String part : parts) {
				adminUserNameList.add(part);
			}

			this.organizationNameList = new LinkedList<String>();

			parts = organizationNames.split(",");

			for (String part : parts) {
				organizationNameList.add(part);
			}

		}

	}

	/**
	 * 
	 */
	@DataBoundConstructor
	public GithubAuthorizationStrategy(String adminUserNames,
			boolean authenticatedUserReadPermission, String organizationNames) {
		super();

		rootACL = new GithubRequireOrganizationMembershipACL(adminUserNames,
				organizationNames, authenticatedUserReadPermission);
	}

	private GithubRequireOrganizationMembershipACL rootACL = null;

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
