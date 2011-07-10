/**
 * 
 */
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Job;
import hudson.plugins.git.GitSCM;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;
import org.kohsuke.stapler.StaplerRequest;

/**
 * @author mocleiri
 * 
 * 
 * 
 */
public class GithubAuthorizationStrategy extends AuthorizationStrategy {

	private static class GithubACL extends ACL {

		private final List<String> adminUserNameList;
		private final boolean authenticatedUserReadPermission;

		@Override
		public boolean hasPermission(Authentication a, Permission permission) {

			String p = a.getName();

			if (p.equals("anonymous"))
				return false;
			
			if (p.equals (SYSTEM.getPrincipal())) {
				return true;
			}

			if (adminUserNameList.contains(p)) {
				// if they are an admin then they have permission
				return true;
			} else {
				if (authenticatedUserReadPermission) {
					
					String[] parts = permission.getId().split("\\.") ;
					if (parts[parts.length-1].toLowerCase().equals("read"))
						
						// if we support authenticated read and this is a read
						// request we allow it
						return true;
				}
			}

			// all other cases we don't allow access.
			return false;
		}

		public GithubACL(List<String> adminUserNameList,
				boolean authenticatedUserReadPermission) {
			super();

			this.authenticatedUserReadPermission = authenticatedUserReadPermission;
			this.adminUserNameList = adminUserNameList;
			
		}

	}

	private static class GithubRequireOrganizationMembershipACL extends ACL {
		
		private final GithubAuthenticationToken authenticationToken;
		private final List<String> organizationNameList;

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * hudson.security.ACL#hasPermission(org.acegisecurity.Authentication,
		 * hudson.security.Permission)
		 */
		@Override
		public boolean hasPermission(Authentication a, Permission permission) {

			String candidateName = a.getName();

			for (String organizationName : this.organizationNameList) {
				
				if (authenticationToken.hasOrganizationPermission(candidateName, organizationName)) {
					
					String[] parts = permission.getId().split("\\.");
					
					String test = parts[1].toLowerCase(); 
					
					if (test.equals("read") || test.equals("build"))
						// check the permission
						return true;
				}
				
			
			}
			
			// no match.
			return false;

		}

		public GithubRequireOrganizationMembershipACL(GithubAuthenticationToken token,
				List<String>organizationNameList) {
			super();
			this.authenticationToken = token;
			this.organizationNameList = organizationNameList;
		}

	}

	private final List<String> adminUserNameList;

	private final boolean authenticatedUserReadPermission;
	
	private final List<String>organizationNameList;

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
		return new GithubACL(this.adminUserNameList,
				this.authenticatedUserReadPermission);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see hudson.security.AuthorizationStrategy#getACL(hudson.model.Job)
	 */
	@Override
	public ACL getACL(Job<?, ?> project) {

		// we will get the project details

		// GitSCM scm = project.getProperty(Git.class);

		// return super.getACL(project);

		Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();

		if (authentication != null
				&& authentication instanceof GithubAuthenticationToken) {

			GithubAuthenticationToken token = (GithubAuthenticationToken) authentication;

			return new GithubRequireOrganizationMembershipACL(token, this.organizationNameList);
		} else {
			// (new GithubAuthenticationToken(accessToken));
			return new GithubACL(adminUserNameList,
					authenticatedUserReadPermission);
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

			String organizationNames = formData.getString ("organizationNames");
			
			return new GithubAuthorizationStrategy(adminUserNames,
					authorizedReadPermission, organizationNames);
		}

	}
}
