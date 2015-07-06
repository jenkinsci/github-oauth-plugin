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

import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import hudson.tasks.Mailer;
import jenkins.model.Jenkins;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHTeam;
import org.kohsuke.github.GHUser;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import static java.util.logging.Level.*;

/**
 *
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses github
 * oauth to verify the user can login.
 *
 * This is based on the MySQLSecurityRealm from the mysql-auth-plugin written by
 * Alex Ackerman.
 */
public class GithubSecurityRealm extends SecurityRealm implements UserDetailsService {
    private static final String DEFAULT_WEB_URI = "https://github.com";
    private static final String DEFAULT_API_URI = "https://api.github.com";
    private static final String DEFAULT_ENTERPRISE_API_SUFFIX = "/api/v3";

    private String githubWebUri;
    private String githubApiUri;
    private String clientID;
    private String clientSecret;

    /**
    * @param githubWebUri The URI to the root of the web UI for GitHub or GitHub Enterprise,
    *                     including the protocol (e.g. https).
    * @param githubApiUri The URI to the root of the API for GitHub or GitHub Enterprise,
    *                     including the protocol (e.g. https).
    * @param clientID The client ID for the created OAuth Application.
    * @param clientSecret The client secret for the created GitHub OAuth Application.
    */
    @DataBoundConstructor
    public GithubSecurityRealm(String githubWebUri, String githubApiUri, String clientID,
            String clientSecret) {
        super();

        this.githubWebUri = Util.fixEmptyAndTrim(githubWebUri);
        this.githubApiUri = Util.fixEmptyAndTrim(githubApiUri);
        this.clientID     = Util.fixEmptyAndTrim(clientID);
        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
    }

    /**
    * @deprecated Use {@link GithubSecurityRealm#GithubSecurityRealm(String, String, String, String)}
    *             instead.
    *
    * @param githubWebUri The URI to the root of the web UI for GitHub or GitHub Enterprise.
    * @param clientID The client ID for the created OAuth Application.
    * @param clientSecret The client secret for the created GitHub OAuth Application.
    */
    @Deprecated
    public GithubSecurityRealm(String githubWebUri, String clientID, String clientSecret) {
        super();

        this.githubWebUri = Util.fixEmptyAndTrim(githubWebUri);
        this.githubApiUri = determineApiUri(this.githubWebUri);
        this.clientID     = Util.fixEmptyAndTrim(clientID);
        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
    }

    private GithubSecurityRealm() {	}

    /**
    * Tries to automatically determine the GitHub API URI based on
    * a GitHub Web URI.
    *
    * @param githubWebUri The URI to the root of the Web UI for GitHub or GitHub Enterprise.
    * @return The expected API URI for the given Web UI
    */
    private String determineApiUri(@SuppressWarnings("hiding") String githubWebUri) {
        if(githubWebUri.equals(DEFAULT_WEB_URI)) {
            return DEFAULT_API_URI;
        } else {
            return githubWebUri + DEFAULT_ENTERPRISE_API_SUFFIX;
        }
    }

    /**
    * @param githubWebUri
    *            the string representation of the URI to the root of the Web UI for
    *            GitHub or GitHub Enterprise.
    */
    private void setGithubWebUri(String githubWebUri) {
        this.githubWebUri = githubWebUri;
    }

    /**
    * @param clientID the clientID to set
    */
    private void setClientID(String clientID) {
        this.clientID = clientID;
    }

    /**
    * @param clientSecret the clientSecret to set
    */
    private void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
    *
    * @return the URI to the API root of GitHub or GitHub Enterprise.
    */
    public String getGithubApiUri() {
        return githubApiUri;
    }

    /**
    * @param githubApiUri the URI to the API root of GitHub or GitHub Enterprise.
    */
    private void setGithubApiUri(String githubApiUri) {
        this.githubApiUri = githubApiUri;
    }

    public static final class ConverterImpl implements Converter {
        @Override
        public boolean canConvert(Class type) {
            return type == GithubSecurityRealm.class;
        }

        @Override
        public void marshal(Object source, HierarchicalStreamWriter writer,
                MarshallingContext context) {

            GithubSecurityRealm realm = (GithubSecurityRealm) source;

            writer.startNode("githubWebUri");
            writer.setValue(realm.getGithubWebUri());
            writer.endNode();

            writer.startNode("githubApiUri");
            writer.setValue(realm.getGithubApiUri());
            writer.endNode();

            writer.startNode("clientID");
            writer.setValue(realm.getClientID());
            writer.endNode();

            writer.startNode("clientSecret");
            writer.setValue(realm.getClientSecret());
            writer.endNode();

        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader,
                UnmarshallingContext context) {
            GithubSecurityRealm realm = new GithubSecurityRealm();

            String node;
            String value;
            while (reader.hasMoreChildren()) {
                reader.moveDown();
                node = reader.getNodeName();
                value = reader.getValue();
                setValue(realm, node, value);
                reader.moveUp();
            }

            if (realm.getGithubWebUri() == null) {
                realm.setGithubWebUri(DEFAULT_WEB_URI);
            }

            if (realm.getGithubApiUri() == null) {
                realm.setGithubApiUri(DEFAULT_API_URI);
            }

            return realm;
        }

        private void setValue(GithubSecurityRealm realm, String node,
                String value) {
            if (node.toLowerCase().equals("clientid")) {
                realm.setClientID(value);
            } else if (node.toLowerCase().equals("clientsecret")) {
                realm.setClientSecret(value);
            } else if (node.toLowerCase().equals("githubweburi")) {
                realm.setGithubWebUri(value);
            } else if (node.toLowerCase().equals("githuburi")) { // backwards compatibility for old field
                realm.setGithubWebUri(value);
                String apiUrl = realm.determineApiUri(value);
                realm.setGithubApiUri(apiUrl);
            } else if (node.toLowerCase().equals("githubapiuri")) {
                realm.setGithubApiUri(value);
            } else
                throw new ConversionException("Invalid node value = " + node);
        }

    }

    /**
    * @return the uri to the web root of Github (varies for Github Enterprise Edition)
    */
    public String getGithubWebUri() {
        return githubWebUri;
    }

    /**
    * @deprecated use {@link org.jenkinsci.plugins.GithubSecurityRealm#getGithubWebUri()} instead.
    * @return the uri to the web root of Github (varies for Github Enterprise Edition)
    */
    @Deprecated
    public String getGithubUri() {
        return getGithubWebUri();
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

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) {
        request.getSession().setAttribute(REFERER_ATTRIBUTE,referer);

        Set<String> scopes = new HashSet<String>();
        for (GitHubOAuthScope s : Jenkins.getInstance().getExtensionList(GitHubOAuthScope.class)) {
            scopes.addAll(s.getScopesToRequest());
        }
        String suffix="";
        if (!scopes.isEmpty()) {
            suffix = "&scope="+Util.join(scopes,",");
        } else {
            // We need repo scope in order to access private repos
            // See https://developer.github.com/v3/oauth/#scopes
            suffix = "&scope=repo,read:org";
        }

        return new HttpRedirect(githubWebUri + "/login/oauth/authorize?client_id="
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

        HttpPost httpost = new HttpPost(githubWebUri
                + "/login/oauth/access_token?" + "client_id=" + clientID + "&"
                + "client_secret=" + clientSecret + "&" + "code=" + code);

        DefaultHttpClient httpclient = new DefaultHttpClient();
        HttpHost proxy = getProxy(httpost);
        if (proxy != null) {
            httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
        }

        org.apache.http.HttpResponse response = httpclient.execute(httpost);

        HttpEntity entity = response.getEntity();

        String content = EntityUtils.toString(entity);

        // When HttpClient instance is no longer needed,
        // shut down the connection manager to ensure
        // immediate deallocation of all system resources
        httpclient.getConnectionManager().shutdown();

        String accessToken = extractToken(content);

        if (accessToken != null && accessToken.trim().length() > 0) {
            // only set the access token if it exists.
            GithubAuthenticationToken auth = new GithubAuthenticationToken(accessToken, getGithubApiUri());
            SecurityContextHolder.getContext().setAuthentication(auth);

            GHUser self = auth.getGitHub().getMyself();
            User u = User.current();
            u.setFullName(self.getName());
            // Set email from github only if empty
            if (!u.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
                u.addProperty(new Mailer.UserProperty(self.getEmail()));
            }

            fireAuthenticated(new GithubOAuthUserDetails(self, auth.getAuthorities()));
        }
        else {
            Log.info("Github did not return an access token.");
        }

        String referer = (String)request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer!=null)  return HttpResponses.redirectTo(referer);
        return HttpResponses.redirectToContextRoot();   // referer should be always there, but be defensive
    }

    /**
     * Calls {@code SecurityListener.fireAuthenticated()} but through reflection to avoid
     * hard dependency on non-LTS core version.
     * TODO delete in 1.569+
     */
    private void fireAuthenticated(UserDetails details) {
        try {
            Class<?> c = Class.forName("jenkins.security.SecurityListener");
            Method m = c.getMethod("fireAuthenticated", UserDetails.class);
            m.invoke(null,details);
        } catch (ClassNotFoundException e) {
            // running with old core
        } catch (NoSuchMethodException e) {
            // running with old core
        } catch (IllegalAccessException e) {
            throw (Error)new IllegalAccessError(e.getMessage()).initCause(e);
        } catch (InvocationTargetException e) {
            LOGGER.log(WARNING, "Failed to invoke fireAuthenticated", e);
        }
    }

    /**
     * Returns the proxy to be used when connecting to the given URI.
     */
    private HttpHost getProxy(HttpUriRequest method) {
        ProxyConfiguration proxy = Jenkins.getInstance().proxy;
        if (proxy==null)    return null;    // defensive check

        Proxy p = proxy.createProxy(method.getURI().getHost());
        switch (p.type()) {
        case DIRECT:
            return null;        // no proxy
        case HTTP:
            InetSocketAddress sa = (InetSocketAddress) p.address();
            return new HttpHost(sa.getHostName(),sa.getPort());
        case SOCKS:
        default:
            return null;        // not supported yet
        }
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

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication)
                    throws AuthenticationException {
                if (authentication instanceof GithubAuthenticationToken)
                    return authentication;
                throw new BadCredentialsException(
                        "Unexpected authentication type: " + authentication);
            }
        }, new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username)
                    throws UsernameNotFoundException, DataAccessException {
                return GithubSecurityRealm.this.loadUserByUsername(username);
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

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        GithubAuthenticationToken authToken = (GithubAuthenticationToken) SecurityContextHolder.getContext()
                                                                                               .getAuthentication();
        if (authToken == null) {
            throw new UserMayOrMayNotExistException("Could not get auth token.");
        }

        try {
            GithubOAuthUserDetails userDetails = authToken.getUserDetails(username);
            if (userDetails == null)
                throw new UsernameNotFoundException("Unknown user: " + username);

            // Check the username is not an homonym of an organization
            GHOrganization ghOrg = authToken.loadOrganization(username);
            if (ghOrg != null) {
                throw new UsernameNotFoundException("user(" + username + ") is also an organization");
            }

            return userDetails;
        } catch (Error e) {
            throw new DataRetrievalFailureException("loadUserByUsername (username=" + username + ")", e);
        }
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupName) throws UsernameNotFoundException, DataAccessException {
        GithubAuthenticationToken authToken = (GithubAuthenticationToken) SecurityContextHolder.getContext()
                                                                                               .getAuthentication();
        if (authToken == null) {
            throw new UsernameNotFoundException("Unknown group: " + groupName);
        }

        try {
            int idx = groupName.indexOf(GithubOAuthGroupDetails.ORG_TEAM_SEPARATOR);
            if (idx > -1 && groupName.length() > idx + 1) { // groupName = "GHOrganization*GHTeam"
                String orgName = groupName.substring(0, idx);
                String teamName = groupName.substring(idx + 1);
                LOGGER.config(String.format("Lookup for team %s in organization %s", teamName, orgName));
                GHTeam ghTeam = authToken.loadTeam(orgName, teamName);
                if (ghTeam == null) {
                    throw new UsernameNotFoundException("Unknown GitHub team: " + teamName + " in organization "
                            + orgName);
                }
                return new GithubOAuthGroupDetails(ghTeam);
            } else { // groupName = "GHOrganization"
                GHOrganization ghOrg = authToken.loadOrganization(groupName);
                if (ghOrg == null) {
                    throw new UsernameNotFoundException("Unknown GitHub organization: " + groupName);
                }
                return new GithubOAuthGroupDetails(ghOrg);
            }
        } catch (Error e) {
            throw new DataRetrievalFailureException("loadGroupByGroupname (groupname=" + groupName + ")", e);
        }
    }

    /**
    * Logger for debugging purposes.
    */
    private static final Logger LOGGER = Logger.getLogger(GithubSecurityRealm.class.getName());

    private static final String REFERER_ATTRIBUTE = GithubSecurityRealm.class.getName()+".referer";
}
