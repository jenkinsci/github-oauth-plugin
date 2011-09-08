/**
 * 
 */
package org.jenkinsci.plugins;

import java.util.LinkedList;
import java.util.List;

import org.acegisecurity.Authentication;
import org.kohsuke.stapler.Stapler;

import hudson.security.ACL;
import hudson.security.Permission;

/**
 * @author Mike
 *
 */
public class GithubRequireOrganizationMembershipACL extends ACL {


		private final List<String> organizationNameList;
		private final List<String> adminUserNameList;
		private final boolean authenticatedUserReadPermission;
		private final boolean allowGithubWebHookPermission;

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

					if (requestURI.matches("^/github-webhook$") && allowGithubWebHookPermission == true) {

							// allow if the permission was configured.

							if (permission.getId().equals(
									"hudson.model.Hudson.Read")
									|| permission.getId().equals(
											"hudson.model.Item.Read"))
								return true;


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
				boolean authenticatedUserReadPermission, boolean allowGithubWebHookPermission) {
			super();
			this.authenticatedUserReadPermission = authenticatedUserReadPermission;
			this.allowGithubWebHookPermission = allowGithubWebHookPermission;

			this.adminUserNameList = new LinkedList<String>();

			String[] parts = adminUserNames.split(",");

			for (String part : parts) {
				adminUserNameList.add(part.trim());
			}

			this.organizationNameList = new LinkedList<String>();

			parts = organizationNames.split(",");

			for (String part : parts) {
				organizationNameList.add(part.trim());
			}

		}

		public List<String> getOrganizationNameList() {
			return organizationNameList;
		}

		public List<String> getAdminUserNameList() {
			return adminUserNameList;
		}

		public boolean isAuthenticatedUserReadPermission() {
			return authenticatedUserReadPermission;
		}

		public boolean isAllowGithubWebHookPermission() {
			return allowGithubWebHookPermission;
		}

		
		

}
