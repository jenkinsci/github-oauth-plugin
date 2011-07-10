/**
 * 
 */
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.kohsuke.stapler.StaplerRequest;

/**
 * @author mocleiri
 * 
 * 
 * 
 */
public class GithubAuthorizationStrategy extends AuthorizationStrategy {

	

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
					

				for (String organizationName : this.organizationNameList) {

					if (authenticationToken.hasOrganizationPermission(
							candidateName, organizationName)) {

						String[] parts = permission.getId().split("\\.");

						String test = parts[parts.length-1].toLowerCase();

						if (test.equals("read") || test.equals("build"))
							// check the permission
							return true;
					}

				}

				// no match.
				return false;
				
			}
			else {
				
				String p = a.getName();

				if (p.equals("anonymous"))
					return false;

				if (p.equals(SYSTEM.getPrincipal())) {
					return true;
				}

				if (adminUserNameList.contains(p)) {
					// if they are an admin then they have permission
					return true;
				} else {
					if (authenticatedUserReadPermission) {

						String[] parts = permission.getId().split("\\.");
						if (parts[parts.length - 1].toLowerCase().equals("read"))

							// if we support authenticated read and this is a read
							// request we allow it
							return true;
					}
				}
				
				return false;

			}
			
			

		}

		public GithubRequireOrganizationMembershipACL(
				List<String> adminUserNameList,
				List<String> organizationNameList,
				boolean authenticatedUserReadPermission) {
			super();
			this.authenticatedUserReadPermission = authenticatedUserReadPermission;
			this.adminUserNameList = adminUserNameList;
			this.organizationNameList = organizationNameList;
			
		}

	}

	private final List<String> adminUserNameList;

	private final boolean authenticatedUserReadPermission;

	private final List<String> organizationNameList;

	/**
	 * 
	 */
	public GithubAuthorizationStrategy(String adminUserNames,
			boolean authenticatedUserReadPermission, String organizationNames) {
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see hudson.security.AuthorizationStrategy#getRootACL()
	 */
	@Override
	public ACL getRootACL() {

	return new GithubRequireOrganizationMembershipACL(this.adminUserNameList, this.organizationNameList,
			this.authenticatedUserReadPermission);

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
			return "/help/security/github-committer-auth-strategy.html";
		}

		@Override
		public GithubAuthorizationStrategy newInstance(StaplerRequest req,
				JSONObject formData) throws FormException {

			String adminUserNames = formData.getString("adminUserNames");
			;
			boolean authorizedReadPermission = formData
					.getBoolean("authenticatedUserReadPermission");

			String organizationNames = formData.getString("organizationNames");

			return new GithubAuthorizationStrategy(adminUserNames,
					authorizedReadPermission, organizationNames);
		}

	}
}
