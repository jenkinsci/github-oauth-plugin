/**
 * 
 */
package org.jenkinsci.plugins;

import java.io.IOException;
import java.util.Map;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHTeam;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;

/**
 * @author mocleiri
 * 
 *         to hold the authentication token from the github oauth process.
 * 
 */
public class GithubAuthenticationToken extends AbstractAuthenticationToken {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private final String accessToken;

	private String userName = null;
	private GitHub gh;

	public GithubAuthenticationToken(String accessToken) {

		super(new GrantedAuthority[] {});

		this.accessToken = accessToken;
		
		gh = GitHub.connectUsingOAuth(accessToken);
		
		try {
			GHUser me = gh.getMyself();
			
			this.userName = me.getLogin();
			
		} catch (IOException e) {
			throw new RuntimeException("failed to load self:", e);
		}
		
		
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.acegisecurity.Authentication#getCredentials()
	 */
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return "";
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see org.acegisecurity.Authentication#getPrincipal()
	 */
	public Object getPrincipal() {
		
		return this.userName;
	}

	public boolean hasPushPermission(String candidateName, String organization,
			String repository) {
		
		try {
			GHOrganization org = gh.getOrganization(organization);
			
			Map<String, GHTeam> teamsMap = org.getTeams();
			
			
			
			return false;
		} catch (IOException e) {
		
			return false;
		}
	}

}
