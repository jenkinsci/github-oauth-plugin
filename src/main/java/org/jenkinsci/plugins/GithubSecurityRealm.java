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
import hudson.model.Fingerprint.RangeSet;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.Permission;
import hudson.security.HudsonPrivateSecurityRealm.Details;
import hudson.security.SecurityRealm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.logging.Logger;

import hudson.tasks.Mailer;
import jenkins.model.Jenkins;
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
import org.apache.bcel.generic.ATHROW;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

/**
 * 
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses github
 * oauth to verify the user can login.
 * 
 * This is based on the MySQLSecurityRealm from the mysql-auth-plugin written by
 * Alex Ackerman.
 */
public class GithubSecurityRealm extends SecurityRealm {

	private static final String DEFAULT_URI = "https://github.com";

    private String githubUri;
	private String clientID;
	private String clientSecret;

	@DataBoundConstructor
	public GithubSecurityRealm(String githubUri, String clientID,
			String clientSecret) {
		super();

		this.githubUri = Util.fixEmptyAndTrim(githubUri);
		this.clientID = Util.fixEmptyAndTrim(clientID);
		this.clientSecret = Util.fixEmptyAndTrim(clientSecret);

	}

	private GithubSecurityRealm() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param githubUri
	 *            the githubUri to set
	 */
	private void setGithubUri(String githubUri) {
		this.githubUri = githubUri;
	}

	/**
	 * @param clientID
	 *            the clientID to set
	 */
	private void setClientID(String clientID) {
		this.clientID = clientID;
	}

	/**
	 * @param clientSecret
	 *            the clientSecret to set
	 */
	private void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public static final class ConverterImpl implements Converter {

		public boolean canConvert(Class type) {
			return type == GithubSecurityRealm.class;
		}

		public void marshal(Object source, HierarchicalStreamWriter writer,
				MarshallingContext context) {

			GithubSecurityRealm realm = (GithubSecurityRealm) source;

			writer.startNode("githubUri");
			writer.setValue(realm.getGithubUri());
			writer.endNode();

			writer.startNode("clientID");
			writer.setValue(realm.getClientID());
			writer.endNode();

			writer.startNode("clientSecret");
			writer.setValue(realm.getClientSecret());
			writer.endNode();
			
		}

		public Object unmarshal(HierarchicalStreamReader reader,
				UnmarshallingContext context) {

			String node = reader.getNodeName();

			reader.moveDown();

			GithubSecurityRealm realm = new GithubSecurityRealm();

			node = reader.getNodeName();

			String value = reader.getValue();

			setValue(realm, node, value);

			reader.moveUp();

			reader.moveDown();

			node = reader.getNodeName();

			value = reader.getValue();

			setValue(realm, node, value);

			reader.moveUp();

			if (reader.hasMoreChildren()) {
				reader.moveDown();

				node = reader.getNodeName();

				value = reader.getValue();

				setValue(realm, node, value);

				reader.moveUp();
			}

			if (realm.getGithubUri() == null) {
				realm.setGithubUri(DEFAULT_URI);
			}

			return realm;
		}

		private void setValue(GithubSecurityRealm realm, String node,
				String value) {

			if (node.toLowerCase().equals("clientid")) {
				realm.setClientID(value);
			} else if (node.toLowerCase().equals("clientsecret")) {
				realm.setClientSecret(value);
			} else if (node.toLowerCase().equals("githuburi")) {
				realm.setGithubUri(value);
			} else
				throw new ConversionException("invalid node value = " + node);

		}

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

	// @Override
	// public Filter createFilter(FilterConfig filterConfig) {
	//
	// return new GithubOAuthAuthenticationFilter();
	// }

	public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer)
			throws IOException {

        request.getSession().setAttribute(REFERER_ATTRIBUTE,referer);
        
        Set<String> scopes = new HashSet<String>();
        for (GitHubOAuthScope s : Jenkins.getInstance().getExtensionList(GitHubOAuthScope.class)) {
            scopes.addAll(s.getScopesToRequest());
        }
        String suffix="";
        if (!scopes.isEmpty()) {
            suffix = "&scope="+Util.join(scopes,",");
        }

		return new HttpRedirect(githubUri + "/login/oauth/authorize?client_id="
				+ clientID + suffix);
	}

	/**
	 * This is where the user comes back to at the end of the OpenID redirect
	 * ping-pong.
	 */
	public HttpResponse doFinishLogin(StaplerRequest request)
			throws IOException {

		String code = request.getParameter("code");
		
		if (code == null || code.trim().length() == 0) {
			Log.info("doFinishLogin: missing code.");
			return HttpResponses.redirectToContextRoot();
		}

		Log.info("test");

		HttpPost httpost = new HttpPost(githubUri
				+ "/login/oauth/access_token?" + "client_id=" + clientID + "&"
				+ "client_secret=" + clientSecret + "&" + "code=" + code);

		DefaultHttpClient httpclient = new DefaultHttpClient();

		org.apache.http.HttpResponse response = httpclient.execute(httpost);

		HttpEntity entity = response.getEntity();

		String content = EntityUtils.toString(entity);

		// When HttpClient instance is no longer needed,
		// shut down the connection manager to ensure
		// immediate deallocation of all system resources
		httpclient.getConnectionManager().shutdown();

		String accessToken = extractToken(content);
		
		if (accessToken != null && accessToken.trim().length() > 0) {

			String githubServer = githubUri.replaceFirst("http.*\\/\\/", "");
			
			// only set the access token if it exists.
            GithubAuthenticationToken auth = new GithubAuthenticationToken(accessToken,githubServer);
            SecurityContextHolder.getContext().setAuthentication(auth);

            GHUser self = auth.getGitHub().getMyself();
            User u = User.current();
            u.setFullName(self.getName());
            u.addProperty(new Mailer.UserProperty(self.getEmail()));
        }
		else {
			Log.info("github did not return an access token.");
		}

        String referer = (String)request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer!=null)  return HttpResponses.redirectTo(referer);
		return HttpResponses.redirectToContextRoot();   // referer should be always there, but be defensive
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

			public Authentication authenticate(Authentication authentication)
					throws AuthenticationException {
				if (authentication instanceof GithubAuthenticationToken)
					return authentication;
				throw new BadCredentialsException(
						"Unexpected authentication type: " + authentication);
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
		GHUser user = null;

		GithubAuthenticationToken authToken =  (GithubAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
		
		if (authToken == null)
			throw new UsernameNotFoundException("no known user: " + username);

		try {
			
			GroupDetails group = loadGroupByGroupname(username);
			
			if (group != null) {
				throw new UsernameNotFoundException ("user("+username+") is also an organization");
			}
			
			user = authToken.loadUser(username);
			
			if (user != null)
				return new GithubOAuthUserDetails(user);
			else
				throw new UsernameNotFoundException("no known user: " + username);
		} catch (IOException e) {
			throw new DataRetrievalFailureException("loadUserByUsername (username=" + username +")", e);
		}
	}

	/**
	 * 
	 * @param groupName
	 * @return
	 * @throws UsernameNotFoundException
	 * @throws DataAccessException
	 */
	@Override
	public GroupDetails loadGroupByGroupname(String groupName)
			throws UsernameNotFoundException, DataAccessException {
		
		GithubAuthenticationToken authToken =  (GithubAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
		
		if(authToken == null)
			throw new UsernameNotFoundException("no known group: " + groupName);

		try {
			GHOrganization org = authToken.loadOrganization(groupName);
			
			if (org != null)
				return new GithubOAuthGroupDetails(org);
			else
				throw new UsernameNotFoundException("no known group: " + groupName);
		} catch (IOException e) {
			throw new DataRetrievalFailureException("loadGroupByGroupname (groupname=" + groupName +")", e);
		}
	}

	
	/**
	 * Logger for debugging purposes.
	 */
	private static final Logger LOGGER = Logger.getLogger(GithubSecurityRealm.class.getName());

    private static final String REFERER_ATTRIBUTE = GithubSecurityRealm.class.getName()+".referer";
}
