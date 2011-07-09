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
import org.kohsuke.stapler.DataBoundConstructor;
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
			
			if (adminUserNameList.contains(p)) {
				// if they are an admin then they have permission
				return true;
			}
			else {
				if (authenticatedUserReadPermission) {
					if (permission.equals(Permission.READ))
						// if we support authenticated read and this is a read request we allow it
						return true;
				}
			}
			
			// all other cases we don't allow access.
			return false;
		}

		public GithubACL(List<String> adminUserNameList, boolean authenticatedUserReadPermission) {
			super();
			
			this.authenticatedUserReadPermission = authenticatedUserReadPermission;
			this.adminUserNameList = adminUserNameList;
		}
		
		
		
	}
	
	private List<String> adminUserNameList;

	private final boolean authenticatedUserReadPermission;
	
	/**
	 * 
	 */
	public GithubAuthorizationStrategy(String adminUserNames, boolean authenticatedUserReadPermission) {
		super();
		this.authenticatedUserReadPermission = authenticatedUserReadPermission;
		
		this.adminUserNameList = new LinkedList<String>();
		
		String[] parts = adminUserNames.split(",");
		
		for (String part : parts) {
			adminUserNameList.add(part);
		}
		
		
		
		
	}

	/* (non-Javadoc)
	 * @see hudson.security.AuthorizationStrategy#getRootACL()
	 */
	@Override
	public ACL getRootACL() {
		return new GithubACL(this.adminUserNameList, this.authenticatedUserReadPermission);
	}

	/* (non-Javadoc)
	 * @see hudson.security.AuthorizationStrategy#getGroups()
	 */
	@Override
	public Collection<String> getGroups() {
		return new ArrayList<String>(0);
	}

	@Extension
    public static final class DescriptorImpl extends Descriptor<AuthorizationStrategy> {
        public String getDisplayName() {
            return "Github Commiter Authorization Strategy";
        }

        public String getHelpFile() {
            return "/help/security/github-committer-auth-strategy.html";
        }

        
        
		@Override
		public GithubAuthorizationStrategy newInstance(StaplerRequest req,
				JSONObject formData) throws FormException {
			
			
			
			String adminUserNames = formData.getString("adminUserNames");;
			boolean authorizedReadPermission =formData.getBoolean("authenticatedUserReadPermission");
			
			return new GithubAuthorizationStrategy(adminUserNames, authorizedReadPermission);
		}

        
       
    }
}
