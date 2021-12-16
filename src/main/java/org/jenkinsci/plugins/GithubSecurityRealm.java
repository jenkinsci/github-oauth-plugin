/**
 The MIT License

Copyright (c) 2011-2016 Michael O'Cleirigh, James Nord, CloudBees, Inc.

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
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.kohsuke.github.GHEmail;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHTeam;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import javax.servlet.http.HttpSession;

/**
 *
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses github
 * oauth to verify the user can login.
 *
 * This is based on the MySQLSecurityRealm from the mysql-auth-plugin written by
 * Alex Ackerman.
 */
public class GithubSecurityRealm extends AbstractPasswordBasedSecurityRealm implements UserDetailsService {
    private static final String DEFAULT_WEB_URI = "https://github.com";
    private static final String DEFAULT_API_URI = "https://api.github.com";
    private static final String DEFAULT_ENTERPRISE_API_SUFFIX = "/api/v3";
    private static final String DEFAULT_OAUTH_SCOPES = "read:org,user:email,repo";

    private String githubWebUri;
    private String githubApiUri;
    private String clientID;
    private Secret clientSecret;
    private String oauthScopes;
    private String[] myScopes;

    /**
     * @param githubWebUri The URI to the root of the web UI for GitHub or GitHub Enterprise,
     *                     including the protocol (e.g. https).
     * @param githubApiUri The URI to the root of the API for GitHub or GitHub Enterprise,
     *                     including the protocol (e.g. https).
     * @param clientID The client ID for the created OAuth Application.
     * @param clientSecret The client secret for the created GitHub OAuth Application.
     * @param oauthScopes A comma separated list of OAuth Scopes to request access to.
     */
    @DataBoundConstructor
    public GithubSecurityRealm(String githubWebUri,
            String githubApiUri,
            String clientID,
            String clientSecret,
            String oauthScopes) {
        super();

        this.githubWebUri = Util.fixEmptyAndTrim(githubWebUri);
        this.githubApiUri = Util.fixEmptyAndTrim(githubApiUri);
        this.clientID     = Util.fixEmptyAndTrim(clientID);
        setClientSecret(Util.fixEmptyAndTrim(clientSecret));
        this.oauthScopes  = Util.fixEmptyAndTrim(oauthScopes);
    }

    private GithubSecurityRealm() {    }

    /**
     * Tries to automatically determine the GitHub API URI based on
     * a GitHub Web URI.
     *
     * @param githubWebUri The URI to the root of the Web UI for GitHub or GitHub Enterprise.
     * @return The expected API URI for the given Web UI
     */
    private String determineApiUri(String githubWebUri) {
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
        this.clientSecret = Secret.fromString(clientSecret);
    }

    /**
     * @param oauthScopes the oauthScopes to set
     */
    private void setOauthScopes(String oauthScopes) {
        this.oauthScopes = oauthScopes;
    }

    /**
     * Checks the security realm for a GitHub OAuth scope.
     * @param scope A scope to check for in the security realm.
     * @return true if security realm has the scope or false if it does not.
     */
    public boolean hasScope(String scope) {
        if(this.myScopes == null) {
            this.myScopes = this.oauthScopes.split(",");
            Arrays.sort(this.myScopes);
        }
        return Arrays.binarySearch(this.myScopes, scope) >= 0;
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

        public boolean canConvert(Class type) {
            return type == GithubSecurityRealm.class;
        }

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
            writer.setValue(realm.getClientSecret().getEncryptedValue());
            writer.endNode();

            writer.startNode("oauthScopes");
            writer.setValue(realm.getOauthScopes());
            writer.endNode();

        }

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
            if (node.equalsIgnoreCase("clientid")) {
                realm.setClientID(value);
            } else if (node.equalsIgnoreCase("clientsecret")) {
                realm.setClientSecret(value);
            } else if (node.equalsIgnoreCase("githubweburi")) {
                realm.setGithubWebUri(value);
            } else if (node.equalsIgnoreCase("githuburi")) { // backwards compatibility for old field
                realm.setGithubWebUri(value);
                String apiUrl = realm.determineApiUri(value);
                realm.setGithubApiUri(apiUrl);
            } else if (node.equalsIgnoreCase("githubapiuri")) {
                realm.setGithubApiUri(value);
            } else if (node.equalsIgnoreCase("oauthscopes")) {
                realm.setOauthScopes(value);
            } else {
                throw new ConversionException("Invalid node value = " + node);
            }
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
    public Secret getClientSecret() {
        return clientSecret;
    }

    /**
     * @return the oauthScopes
     */
    public String getOauthScopes() {
        return oauthScopes;
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @QueryParameter String from, @Header("Referer") final String referer)
            throws IOException {
        // https://tools.ietf.org/html/rfc6749#section-10.10 dictates that probability that an attacker guesses the string
        // SHOULD be less than or equal to 2^(-160) and our Strings consist of 65 chars. (65^27 ~= 2^160)
        final String state = getSecureRandomString(27);
        String redirectOnFinish;
        if (from != null && Util.isSafeToRedirectTo(from)) {
            redirectOnFinish = from;
        } else if (referer != null && (referer.startsWith(Jenkins.get().getRootUrl()) || Util.isSafeToRedirectTo(referer))) {
            redirectOnFinish = referer;
        } else {
            redirectOnFinish = Jenkins.get().getRootUrl();
        }

        request.getSession().setAttribute(REFERER_ATTRIBUTE, redirectOnFinish);
        request.getSession().setAttribute(STATE_ATTRIBUTE, state);

        Set<String> scopes = new HashSet<>();
        for (GitHubOAuthScope s : Jenkins.get().getExtensionList(GitHubOAuthScope.class)) {
            scopes.addAll(s.getScopesToRequest());
        }
        String suffix="";
        if (!scopes.isEmpty()) {
            suffix = "&scope="+Util.join(scopes,",")+"&state="+state;
        } else {
            // We need repo scope in order to access private repos
            // See https://developer.github.com/v3/oauth/#scopes
            suffix = "&scope=" + oauthScopes +"&state="+state;
        }

        return new HttpRedirect(githubWebUri + "/login/oauth/authorize?client_id="
                + clientID + suffix);
    }

    /**
     * This is where the user comes back to at the end of the OAuth redirect
     * ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request)
            throws IOException {
        String code = request.getParameter("code");
        String state = request.getParameter(STATE_ATTRIBUTE);
        String referer = (String)request.getSession().getAttribute(REFERER_ATTRIBUTE);
        String expectedState = (String)request.getSession().getAttribute(STATE_ATTRIBUTE);

        if (code == null || code.trim().length() == 0) {
            LOGGER.info("doFinishLogin: missing code.");
            return HttpResponses.redirectToContextRoot();
        }

        if (state == null){
            LOGGER.info("doFinishLogin: missing state parameter from Github response.");
            return HttpResponses.redirectToContextRoot();
        } else if (expectedState == null){
            LOGGER.info("doFinishLogin: missing state parameter from user's session.");
            return HttpResponses.redirectToContextRoot();
        } else if (!state.equals(expectedState)){
            LOGGER.info("state parameter value ["+state+"] does not match the expected one ["+expectedState+"]");
            return HttpResponses.redirectToContextRoot();
        }


        String accessToken = getAccessToken(code);

        if (accessToken != null && accessToken.trim().length() > 0) {
            // only set the access token if it exists.
            GithubAuthenticationToken auth = new GithubAuthenticationToken(accessToken, getGithubApiUri());

            HttpSession session = request.getSession(false);
            if(session != null){
                // avoid session fixation
                session.invalidate();
            }
            request.getSession(true);

            SecurityContextHolder.getContext().setAuthentication(auth);

            GHMyself self = auth.getMyself();
            User u = User.current();
            if (u == null) {
                throw new IllegalStateException("Can't find user");
            }

            GithubSecretStorage.put(u, accessToken);

            u.setFullName(self.getName());
            // Set email from github only if empty
            if (!u.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
                if(hasScope("user") || hasScope("user:email")) {
                    String primary_email = null;
                    for(GHEmail e : self.getEmails2()) {
                        if(e.isPrimary()) {
                            primary_email = e.getEmail();
                        }
                    }
                    if(primary_email != null) {
                        u.addProperty(new Mailer.UserProperty(primary_email));
                    }
                } else {
                    u.addProperty(new Mailer.UserProperty(auth.getGitHub().getMyself().getEmail()));
                }
            }

            SecurityListener.fireAuthenticated(new GithubOAuthUserDetails(self.getLogin(), auth.getAuthorities()));

            // While LastGrantedAuthorities are triggered by that event, we cannot trigger it there
            // or modifications in organizations will be not reflected when using API Token, due to that caching
            // SecurityListener.fireLoggedIn(self.getLogin());
        } else {
            LOGGER.info("Github did not return an access token.");
        }

        if (referer!=null)  return HttpResponses.redirectTo(referer);
        return HttpResponses.redirectToContextRoot();   // referer should be always there, but be defensive
    }

    @Nullable
    private String getAccessToken(@NonNull String code) throws IOException {
        String content;
        HttpPost httpost = new HttpPost(githubWebUri
                + "/login/oauth/access_token?" + "client_id=" + clientID + "&"
                + "client_secret=" + clientSecret.getPlainText() + "&" + "code=" + code);

        try (CloseableHttpClient httpClient = configureClientWithProxy(httpost)) {
            org.apache.http.HttpResponse response = httpClient.execute(httpost);
            HttpEntity entity = response.getEntity();
            content = EntityUtils.toString(entity);

        }
        String[] parts = content.split("&");
        for (String part : parts) {
            if (part.startsWith("access_token=")) {
                String[] tokenParts = part.split("=");
                return tokenParts[1];
            }
        }
        return null;
    }

    private CloseableHttpClient configureClientWithProxy(HttpPost postLocation) {
        ProxyConfiguration proxyConfiguration = Jenkins.get().proxy;

        if (proxyConfiguration == null) return HttpClients.createDefault();

        HttpHost proxyHost = getProxy(proxyConfiguration, postLocation.getURI().getHost());

        HttpClientBuilder httpClientBuilder = HttpClients.custom();

        if (proxyHost != null) {
            RequestConfig requestConfig = RequestConfig.custom()
                    .setProxy(proxyHost)
                    .build();

            postLocation.setConfig(requestConfig);

            if(proxyConfiguration.getUserName() != null && proxyConfiguration.getSecretPassword() != null ) {
                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(
                        new AuthScope(proxyHost.getHostName(), proxyHost.getPort()),
                        new UsernamePasswordCredentials(proxyConfiguration.getUserName(), proxyConfiguration.getSecretPassword().getPlainText()));
                httpClientBuilder.setDefaultCredentialsProvider(credsProvider);
            }
        }

        return httpClientBuilder.build();
    }


    /**
     * Generates a random URL Safe String of n characters
     */
    private String getSecureRandomString(int n) {
        if (n < 0){
            throw new IllegalArgumentException("Length must be a positive integer");
        }
        // See RFC3986
        final String urlSafeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n ; i++){
            sb.append(urlSafeChars.charAt(SECURE_RANDOM.nextInt(urlSafeChars.length())));
        }
        return sb.toString();
    }
    /**
     * Returns the proxy to be used when connecting to the given URI.
     */
    private HttpHost getProxy(ProxyConfiguration proxy, String host) {
        Proxy p = proxy.createProxy(host);
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
                if (authentication instanceof UsernamePasswordAuthenticationToken)
                    try {
                        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
                        GithubAuthenticationToken github = new GithubAuthenticationToken(token.getCredentials().toString(), getGithubApiUri());
                        SecurityContextHolder.getContext().setAuthentication(github);

                        User user = User.getById(token.getName(), false);
                        if(user != null){
                            GithubSecretStorage.put(user, token.getCredentials().toString());
                        }

                        SecurityListener.fireAuthenticated(new GithubOAuthUserDetails(token.getName(), github.getAuthorities()));

                        return github;
                    } catch (IOException e) {
                            throw new RuntimeException(e);
                    }
                throw new BadCredentialsException(
                        "Unexpected authentication type: " + authentication);
            }
        }, GithubSecurityRealm.this::loadUserByUsername);
    }

    @Override
    protected GithubOAuthUserDetails authenticate(String username, String password) throws AuthenticationException {
        try {
            GithubAuthenticationToken github = new GithubAuthenticationToken(password, getGithubApiUri());
            if(username.equals(github.getPrincipal())) {
                SecurityContextHolder.getContext().setAuthentication(github);
                return github.getUserDetails(username);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        throw new BadCredentialsException("Invalid GitHub username or personal access token: " + username);
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        // if we just redirect to the root and anonymous does not have Overall read then we will start a login all over again.
        // we are actually anonymous here as the security context has been cleared
        Jenkins j = Jenkins.get();
        if (j.hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl(req, auth);
        }
        return req.getContextPath()+ "/" + GithubLogoutAction.POST_LOGOUT_URL;
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

        public String getDefaultGithubWebUri() {
            return DEFAULT_WEB_URI;
        }

        public String getDefaultGithubApiUri() {
            return DEFAULT_API_URI;
        }

        public String getDefaultOauthScopes() {
            return DEFAULT_OAUTH_SCOPES;
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

    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    /**
     *
     * @param username username to lookup
     * @return userDetails
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
        //username is in org*team format
        if(username.contains(GithubOAuthGroupDetails.ORG_TEAM_SEPARATOR)) {
            throw new UsernameNotFoundException("Using org*team format instead of username: " + username);
        }

        User localUser = User.getById(username, false);

        Authentication token = SecurityContextHolder.getContext().getAuthentication();

        try {
            if(localUser != null && GithubSecretStorage.contains(localUser)) {
                String accessToken = GithubSecretStorage.retrieve(localUser);
                token = new GithubAuthenticationToken(accessToken, getGithubApiUri());
            }
        } catch(IOException | UsernameNotFoundException e) {
            if(e instanceof IOException) {
                throw new UserMayOrMayNotExistException("Could not connect to GitHub API server, target URL = " + getGithubApiUri(), e);
            } else {
                // user not found so continuing normally re-using the current context holder
                LOGGER.log(Level.FINE, "Attempted to impersonate " + username + " but token in user property was invalid.");
            }
        }

        GithubAuthenticationToken authToken;

        if (token instanceof GithubAuthenticationToken) {
            authToken = (GithubAuthenticationToken) token;
        } else {
            throw new UserMayOrMayNotExistException("Unexpected authentication type: " + token);
        }

        /**
         * Always lookup the local user first. If we can't resolve it then we can burn an API request to Github for this user
         * Taken from hudson.security.HudsonPrivateSecurityRealm#loadUserByUsername(java.lang.String)
         */
        if (localUser != null) {
            return new GithubOAuthUserDetails(username, authToken);
        }

        try {
            GithubOAuthUserDetails userDetails = authToken.getUserDetails(username);
            if (userDetails == null) {
                throw new UsernameNotFoundException("Unknown user: " + username);
            }

            // Check the username is not an homonym of an organization
            GHOrganization ghOrg = authToken.loadOrganization(username);
            if (ghOrg != null) {
                throw new UsernameNotFoundException("user(" + username + ") is also an organization");
            }

            return userDetails;
        } catch (IOException | Error e) {
            throw new DataRetrievalFailureException("loadUserByUsername (username=" + username +")", e);
        }
    }

    /**
     * Compare an object against this instance for equivalence.
     * @param object An object to campare this instance to.
     * @return true if the objects are the same instance and configuration.
     */
    @Override
    public boolean equals(Object object){
        if(object instanceof GithubSecurityRealm) {
            GithubSecurityRealm obj = (GithubSecurityRealm) object;
            return this.getGithubWebUri().equals(obj.getGithubWebUri()) &&
                this.getGithubApiUri().equals(obj.getGithubApiUri()) &&
                this.getClientID().equals(obj.getClientID()) &&
                this.getClientSecret().equals(obj.getClientSecret()) &&
                this.getOauthScopes().equals(obj.getOauthScopes());
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder()
                .append(this.getGithubWebUri())
                .append(this.getGithubApiUri())
                .append(this.getClientID())
                .append(this.getClientSecret())
                .append(this.getOauthScopes())
                .toHashCode();
    }

    /**
     *
     * @param groupName groupName to look up
     * @return groupDetails
     */
    @Override
    public GroupDetails loadGroupByGroupname(String groupName)
            throws UsernameNotFoundException, DataAccessException {
        GithubAuthenticationToken authToken =  (GithubAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        if(authToken == null)
            throw new UsernameNotFoundException("No known group: " + groupName);

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
    private static final String STATE_ATTRIBUTE = "state";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

}
