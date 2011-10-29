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
import hudson.model.Descriptor;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

import java.io.IOException;
import java.util.logging.Logger;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

/**
 * 
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses github
 * oauth to verify the user can login.
 * 
 * This is based on the MySQLSecurityRealm from the mysql-auth-plugin written by
 * Alex Ackerman.
 */
public class GithubSecurityRealm extends SecurityRealm {

	private String githubUri;
	private String clientID;
	private String clientSecret;

	@DataBoundConstructor
	public GithubSecurityRealm(String githubUri, String clientID, String clientSecret) {
		super();

		this.githubUri = Util.fixEmptyAndTrim(githubUri);
		this.clientID = Util.fixEmptyAndTrim(clientID);
		this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
		
	}

	/**
	 * @return the uri to Github (varies for Github Enterprise Edition)
	 */
	public String getGithubUri() {
		return githubUri;
	}
	
     /**
	 * @return the clientID
	 */
	public String getClientID() {
		return clientID;
	}

	/**
	 * @return the clientSecret
	 */
	public String getClientSecret() {
		return clientSecret;
	}

	
	
//	@Override
//	public Filter createFilter(FilterConfig filterConfig) {
//		
//		return new GithubOAuthAuthenticationFilter();
//	}

	public HttpResponse doCommenceLogin(@Header("Referer") final String referer)
			throws IOException {

		return new HttpRedirect(
				githubUri + "/login/oauth/authorize?client_id="
						+ clientID);
		
		// we only need the readonly scope to get the group membership info.
		// if we extend for other repo aware details the token scope may need to be specified.
		// this can be done by adding a scope paramter to the above url.
		//  + "&scope=user,public_repo,repo"

	}

	/**
	 * This is where the user comes back to at the end of the OpenID redirect
	 * ping-pong.
	 */
	public HttpResponse doFinishLogin(StaplerRequest request)
			throws IOException {

		String code = request.getParameter("code");

		Log.info("test");

		HttpPost httpost = new HttpPost(
				githubUri + "/login/oauth/access_token?" + "client_id="
						+ clientID + "&" + "client_secret=" + clientSecret
						+ "&" + "code=" + code);

		DefaultHttpClient httpclient = new DefaultHttpClient();

		org.apache.http.HttpResponse response = httpclient.execute(httpost);

		HttpEntity entity = response.getEntity();

		String content = EntityUtils.toString(entity);

		// When HttpClient instance is no longer needed,
		// shut down the connection manager to ensure
		// immediate deallocation of all system resources
		httpclient.getConnectionManager().shutdown();

		String accessToken = extractToken(content);

		SecurityContextHolder.getContext().setAuthentication(
				new GithubAuthenticationToken(accessToken));

		return HttpResponses.redirectToContextRoot();
	}

	private String extractToken(String content) {

		String parts[] = content.split("&");

		for (String part : parts) {

			if (content.contains("access_token")) {

				String tokenParts[] = part.split("=");

				return tokenParts[1];
			}

			// fall through
		}

		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see hudson.security.SecurityRealm#allowsSignup()
	 */
	@Override
	public boolean allowsSignup() {
		return false;
	}

	@Override
	public SecurityComponents createSecurityComponents() {
		
           
		
		return new SecurityComponents(new AuthenticationManager() {
			
				 public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		                if (authentication instanceof GithubAuthenticationToken)
		                    return authentication;
		                throw new BadCredentialsException("Unexpected authentication type: "+authentication);
			}
		}, new UserDetailsService() {
			public UserDetails loadUserByUsername(String username)
					throws UsernameNotFoundException, DataAccessException {
				throw new UsernameNotFoundException(username);
			}
		});
	}

	
	@Override
	public String getLoginUrl() {

		return "securityRealm/commenceLogin";
	}

	@Extension
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

		@Override
		public String getHelpFile() {
			return "/plugin/github-oauth/help/help-security-realm.html";
		}

		@Override
		public String getDisplayName() {
			return "Github Authentication Plugin";
		}

		public DescriptorImpl() {
			super();
			// TODO Auto-generated constructor stub
		}

		public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
			super(clazz);
			// TODO Auto-generated constructor stub
		}

	}

	/**
	 * 
	 * @param username
	 * @return
	 * @throws UsernameNotFoundException
	 * @throws DataAccessException
	 */
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException, DataAccessException {
		UserDetails user = null;
		String connectionString;

		if (true)
			throw new UsernameNotFoundException("implemtnation required");

		return user;
	}

	/**
	 * 
	 * @param groupname
	 * @return
	 * @throws UsernameNotFoundException
	 * @throws DataAccessException
	 */
	@Override
	public GroupDetails loadGroupByGroupname(String groupname)
			throws UsernameNotFoundException, DataAccessException {
		LOGGER.warning("ERROR: Group lookup is not supported.");
		throw new UsernameNotFoundException(
				"GithubSecurityRealm: Non-supported function");
	}

	/**
	 * Logger for debugging purposes.
	 */
	private static final Logger LOGGER = Logger
			.getLogger(GithubSecurityRealm.class.getName());

}
