/**
 * 
 */
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.Hudson;
import hudson.security.FederatedLoginServiceUserProperty;
import hudson.security.FederatedLoginService;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;

import org.jfree.util.Log;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

/**
 * @author mike
 *
 */
@Extension
public class GithubOAuthLoginService extends FederatedLoginService {

	/**
	 * 
	 */
	public GithubOAuthLoginService() {
		// TODO Auto-generated constructor stub
	}

	
	/* (non-Javadoc)
	 * @see hudson.security.FederatedLoginService#getUrlName()
	 */
	@Override
	public String getUrlName() {
		return "github";
	}

	 
	/* (non-Javadoc)
	 * @see hudson.security.FederatedLoginService#getUserPropertyClass()
	 */
	@Override
	public Class<? extends FederatedLoginServiceUserProperty> getUserPropertyClass() {
		return GithubOAuthLoginServiceUserProperty.class;
	}

	
	private class GithubOAuthLoginServiceUserProperty extends FederatedLoginServiceUserProperty {

		public GithubOAuthLoginServiceUserProperty(
				Collection<String> identifiers) {
			super(identifiers);
			// TODO Auto-generated constructor stub
		}
		
		
		
	}
	
	 public HttpResponse doStartLogin(@QueryParameter String code) throws IOException {
		 
		 // this is step two.
		 
		 // we do an http post using the code and the clientid, client secret from the githuboauthSecurityRealm
		 
		
		 
		 return new HttpResponse() {
			
			public void generateResponse(StaplerRequest req, StaplerResponse rsp,
					Object node) throws IOException, ServletException {
				
				
				 ExtensionList<GithubSecurityRealm> list = Hudson.getInstance().getExtensionList(GithubSecurityRealm.class);
				 
				 GithubSecurityRealm realm = list.get(0);
				 
				 String clientID = realm.getClientID();
				 
				 String clientSecret = realm.getClientSecret();
				 
				 Log.info("test"); 
				
				
			}
		};
		 
		 
		 
	 }
	 
	 
	private class GithubOAuthIdentity extends FederatedIdentity {

		private String proNoun;
		private String email;
		private String fullName;
		private String nickName;
		private String id;

		

		public GithubOAuthIdentity() {
			super();
			// TODO Auto-generated constructor stub
		}

		public GithubOAuthIdentity(String id, String nickName, String email,
				String proNoun, String fullName) {
			super();
			this.id = id;
			this.nickName = nickName;
			this.email = email;
			this.proNoun = proNoun;
			this.fullName = fullName;
		}

		@Override
		public String getIdentifier() {
			return id;
		}

		@Override
		public String getNickname() {
			return nickName;
		}

		@Override
		public String getFullName() {
			return fullName;
		}

		@Override
		public String getEmailAddress() {
			return email;
		}

		@Override
		public String getPronoun() {
			return proNoun;
		}
		
		
	}
}
