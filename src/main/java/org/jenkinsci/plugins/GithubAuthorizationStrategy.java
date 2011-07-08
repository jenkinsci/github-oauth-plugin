/**
 * 
 */
package org.jenkinsci.plugins;

import java.util.ArrayList;
import java.util.Collection;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.kohsuke.stapler.StaplerRequest;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.LegacyAuthorizationStrategy;
import hudson.security.Messages;
import hudson.security.Permission;

/**
 * @author mocleiri
 * 
 * 
 *
 */
public class GithubAuthorizationStrategy extends AuthorizationStrategy {

	private static class GithubACL extends ACL {

		@Override
		public boolean hasPermission(Authentication a, Permission permission) {
			// TODO Auto-generated method stub
			return true;
		}

		public GithubACL() {
			super();
			// TODO Auto-generated constructor stub
		}
		
		
		
	}
	
	private static GithubACL ROOT_ACL = new GithubACL();
	
	/**
	 * 
	 */
	public GithubAuthorizationStrategy() {
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see hudson.security.AuthorizationStrategy#getRootACL()
	 */
	@Override
	public ACL getRootACL() {
		return ROOT_ACL;
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
			
			return new GithubAuthorizationStrategy();
		}

        
       
    }
}
