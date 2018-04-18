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
import hudson.FilePath;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.cli.CLICommand;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.CliAuthenticator;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.MasterToSlaveCallable;
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
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;
import org.kohsuke.args4j.Option;
import org.kohsuke.github.GHEmail;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHTeam;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import java.io.Console;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

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
    private static final Boolean DEFAULT_FORCE_GITHUB_EMAIL = false;

    private String githubWebUri;
    private String githubApiUri;
    private String clientID;
    private Secret clientSecret;
    private String oauthScopes;
    private String emailDomains;
    private Boolean forceGithubEmail;
    private String[] myScopes;

    /**
     * @param githubWebUri The URI to the root of the web UI for GitHub or GitHub Enterprise,
     *                     including the protocol (e.g. https).
     * @param githubApiUri The URI to the root of the API for GitHub or GitHub Enterprise,
     *                     including the protocol (e.g. https).
     * @param clientID The client ID for the created OAuth Application.
     * @param clientSecret The client secret for the created GitHub OAuth Application.
     * @param oauthScopes A comma separated list of OAuth Scopes to request access to.
     * @param emailDomains An optional comma separated list of domain(s) to select for email
     * @param forceGithubEmail Force the email from github to override the one in the profile
     */
    @DataBoundConstructor
    public GithubSecurityRealm(String githubWebUri,
            String githubApiUri,
            String clientID,
            String clientSecret,
            String oauthScopes,
            String emailDomains,
            Boolean forceGithubEmail) {
        super();

        this.githubWebUri = Util.fixEmptyAndTrim(githubWebUri);
        this.githubApiUri = Util.fixEmptyAndTrim(githubApiUri);
        this.clientID     = Util.fixEmptyAndTrim(clientID);
        setClientSecret(Util.fixEmptyAndTrim(clientSecret));
        this.oauthScopes  = Util.fixEmptyAndTrim(oauthScopes);
        this.emailDomains  = emailDomains.trim();
        this.forceGithubEmail  = forceGithubEmail;
    }

    /**
       This method is deprecated.
       @deprecated use GithubSecurityRealm(githubWebUri, githubApiUri, clientID, clientSecret, oauthScopes, emailDomains, forceGithubEmail)
     */
    @Deprecated
    public GithubSecurityRealm(String githubWebUri,
                 String githubApiUri,
                 String clientID,
                 String clientSecret,
                 String oauthScopes) {
        this(githubWebUri, githubApiUri, clientID, clientSecret, oauthScopes, "", false);
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
     * @param emailDomains the emailDomains to set
     */
    private void setEmailDomains(String emailDomains) {
        this.emailDomains = emailDomains;
    }

    /**
     * @param forceGithubEmail the forceGithubEmail to set
     */
    private void setForceGithubEmail(Boolean forceGithubEmail) {
        this.forceGithubEmail = forceGithubEmail;
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

            writer.startNode("emailDomains");
            writer.setValue(realm.getEmailDomains());
            writer.endNode();

            writer.startNode("forceGithubEmail");
            //TODO: Is there a better way to do this?
            if (realm.getForceGithubEmail()) {
                writer.setValue("true");
            }
            else {
                writer.setValue("false");
            }
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

            if (realm.getForceGithubEmail() == null) {
                realm.setForceGithubEmail(DEFAULT_FORCE_GITHUB_EMAIL);
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
            } else if (node.toLowerCase().equals("oauthscopes")) {
                realm.setOauthScopes(value);
            } else if (node.toLowerCase().equals("emaildomains")) {
                realm.setEmailDomains(value);
            } else if (node.toLowerCase().equals("forcegithubemail")) {
                if (value.toLowerCase().equals("true")){
                    realm.setForceGithubEmail(true);
                }
                else {
                    realm.setForceGithubEmail(false);
                }
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

    /**
     * @return the emailDomains
     */
    public String getEmailDomains() {
        return emailDomains;
    }

    /**
     * @return the forceGithubEmail
     */
    public Boolean getForceGithubEmail() {
        return forceGithubEmail;
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer)
            throws IOException {
        request.getSession().setAttribute(REFERER_ATTRIBUTE,referer);

        Set<String> scopes = new HashSet<>();
        for (GitHubOAuthScope s : getJenkins().getExtensionList(GitHubOAuthScope.class)) {
            scopes.addAll(s.getScopesToRequest());
        }
        String suffix="";
        if (!scopes.isEmpty()) {
            suffix = "&scope="+Util.join(scopes,",");
        } else {
            // We need repo scope in order to access private repos
            // See https://developer.github.com/v3/oauth/#scopes
            suffix = "&scope=" + oauthScopes;
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

        if (code == null || code.trim().length() == 0) {
            Log.info("doFinishLogin: missing code.");
            return HttpResponses.redirectToContextRoot();
        }

        String accessToken = getAccessToken(code);

        if (accessToken != null && accessToken.trim().length() > 0) {
            // only set the access token if it exists.
            GithubAuthenticationToken auth = new GithubAuthenticationToken(accessToken, getGithubApiUri());
            SecurityContextHolder.getContext().setAuthentication(auth);

            GHMyself self = auth.getMyself();
            User u = User.current();
            if (u == null) {
                throw new IllegalStateException("Can't find user");
            }

            GithubSecretStorage.put(u, accessToken);

            u.setFullName(self.getName());
            // Set email from github only if empty or forceGithubEmail flag is set
            if (forceGithubEmail || !u.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
                if(hasScope("user") || hasScope("user:email")) {
                    String primary_email = null;
                    String domain_email = null;
                    if (emailDomains != null) {
                        LOGGER.log(Level.FINE, "Searching for email of github user \"" + u.getId() + "\" that match domain(s) \"" + emailDomains + "\"");
                        for (String emailDomain : emailDomains.split(",")) {
                            for(GHEmail e : self.getEmails2()) {
                                LOGGER.log(Level.FINE, "Checking if email \"" + e.getEmail() + "\" matches domain \"" + emailDomain + "\" for github user \"" + u.getId() + "\"");
                                if(e.getEmail().endsWith("@" + emailDomain)) {
                                    domain_email = e.getEmail();
                                    LOGGER.log(Level.FINE, "Email \"" + e.getEmail() + "\" matches domain \"" + emailDomain + "\" for github user \"" + u.getId() + "\"");
                                    break;
                                }
                            }
                            if (domain_email != null) {
                                LOGGER.log(Level.FINE, "Setting email for github user \"" + u.getId() + "\" to \"" + domain_email + "\" due to matching domain in domain list");
                                u.addProperty(new Mailer.UserProperty(domain_email));
                                break;
                            }
                        }
                    }
                    if (domain_email == null) {
                        LOGGER.log(Level.FINE, "Getting primary email for github user \"" + u.getId() + "\"");
                        for(GHEmail e : self.getEmails2()) {
                            LOGGER.log(Level.FINE, "Checking if email \"" + e.getEmail() + "\" is primary email for github user \"" + u.getId() + "\"");
                            if (e.isPrimary()) {
                                primary_email = e.getEmail();
                                LOGGER.log(Level.FINE, "Setting email for github user \"" + u.getId() + "\" to primary address \"" + primary_email + "\"");
                                u.addProperty(new Mailer.UserProperty(primary_email));
                                break;
                            }
                        }
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
            Log.info("Github did not return an access token.");
        }

        String referer = (String)request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer!=null)  return HttpResponses.redirectTo(referer);
        return HttpResponses.redirectToContextRoot();   // referer should be always there, but be defensive
    }

    @Nullable
    private String getAccessToken(@Nonnull String code) throws IOException {
        String content;
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpost = new HttpPost(githubWebUri
                    + "/login/oauth/access_token?" + "client_id=" + clientID + "&"
                    + "client_secret=" + clientSecret + "&" + "code=" + code);
            HttpHost proxy = getProxy(httpost);
            if (proxy != null) {
                RequestConfig requestConfig = RequestConfig.custom().setProxy(proxy).build();
                httpost.setConfig(requestConfig);
            }
            org.apache.http.HttpResponse response = httpClient.execute(httpost);
            HttpEntity entity = response.getEntity();
            content = EntityUtils.toString(entity);

        }
        String parts[] = content.split("&");
        for (String part : parts) {
            if (part.startsWith("access_token=")) {
                String tokenParts[] = part.split("=");
                return tokenParts[1];
            }
        }
        return null;
    }

    /**
     * Returns the proxy to be used when connecting to the given URI.
     */
    private HttpHost getProxy(HttpUriRequest method) throws URIException {
        ProxyConfiguration proxy = getJenkins().proxy;
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
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername(String username)
                    throws UsernameNotFoundException, DataAccessException {
                return GithubSecurityRealm.this.loadUserByUsername(username);
            }
        });
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
    public CliAuthenticator createCliAuthenticator(final CLICommand command) {
        return new CliAuthenticator() {
            @Option(name="--username",usage="GitHub username to authenticate yourself to Jenkins.")
            public String userName;

            @Option(name="--password",usage="GitHub personal access token. Note that passing a password in arguments is insecure.")
            public String password;

            @Option(name="--password-file",usage="File that contains the personal access token.")
            public String passwordFile;

            public Authentication authenticate() throws AuthenticationException, IOException, InterruptedException {
                if(userName == null) {
                    // no authentication parameter. fallback to the transport
                    return command.getTransportAuthentication();
                }
                if(passwordFile != null) {
                    try {
                        password = new FilePath(command.channel, passwordFile).readToString().trim();
                    } catch (IOException e) {
                        throw new BadCredentialsException("Failed to read " + passwordFile, e);
                    }
                }
                if(password == null) {
                    password = command.channel.call(new InteractivelyAskForPassword());
                }

                if(password == null) {
                    throw new BadCredentialsException("No GitHub personal access token specified.");
                }
                GithubSecurityRealm.this.authenticate(userName, password);
                return new GithubAuthenticationToken(password, getGithubApiUri());
            }
        };
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        // if we just redirect to the root and anonymous does not have Overall read then we will start a login all over again.
        // we are actually anonymous here as the security context has been cleared
        Jenkins j = Jenkins.getInstance();
        assert j != null;
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

        public Boolean getDefaultForceGithubEmail() {
            return DEFAULT_FORCE_GITHUB_EMAIL;
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
     * @throws UserMayOrMayNotExistException
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
        //username is in org*team format
        if(username.indexOf(GithubOAuthGroupDetails.ORG_TEAM_SEPARATOR) >= 0 ) {
            throw new UsernameNotFoundException("Using org*team format instead of username: " + username);
        }

        User localUser = User.getById(username, false);

        Authentication token = SecurityContextHolder.getContext().getAuthentication();

        if (token == null) {
            if(localUser != null && GithubSecretStorage.contains(localUser)){
                String accessToken = GithubSecretStorage.retrieve(localUser);
                try {
                    token = new GithubAuthenticationToken(accessToken, getGithubApiUri());
                } catch (IOException e) {
                    throw new UserMayOrMayNotExistException("Could not connect to GitHub API server, target URL = " + getGithubApiUri(), e);
                }
                SecurityContextHolder.getContext().setAuthentication(token);
            }else{
                throw new UserMayOrMayNotExistException("Could not get auth token.");
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
            if (userDetails == null)
                throw new UsernameNotFoundException("Unknown user: " + username);

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
                this.getOauthScopes().equals(obj.getOauthScopes()) &&
                this.getEmailDomains().equals(obj.getEmailDomains()) &&
                this.getForceGithubEmail().equals(obj.getForceGithubEmail());
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
     * @throws UsernameNotFoundException
     * @throws DataAccessException
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

    static Jenkins getJenkins() {
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        return jenkins;
    }

    /**
     * Logger for debugging purposes.
     */
    private static final Logger LOGGER = Logger.getLogger(GithubSecurityRealm.class.getName());

    private static final String REFERER_ATTRIBUTE = GithubSecurityRealm.class.getName()+".referer";

    /**
     * Asks for the password.
     */
    private static class InteractivelyAskForPassword extends MasterToSlaveCallable<String,IOException> {
        public String call() throws IOException {
            Console console = System.console();
            if(console == null) {
                return null;    // no terminal
            }
            char[] w = console.readPassword("GitHub Personal Access Token: ");
            if(w==null) {
                return null;
            }
            return new String(w);
        }
        private static final long serialVersionUID = 1L;
    }
}
