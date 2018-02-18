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

import com.google.common.base.Optional;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.OkUrlFactory;

import hudson.security.Permission;
import hudson.security.SecurityRealm;
import hudson.model.Item;
import jenkins.model.Jenkins;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHPersonSet;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GHTeam;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.RateLimitHandler;
import org.kohsuke.github.extras.OkHttpConnector;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.Nonnull;


/**
 * @author mocleiri
 *
 *         to hold the authentication token from the github oauth process.
 *
 */
public class GithubAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 2L;

    private final String accessToken;
    private final String githubServer;
    private final String userName;

    private transient GitHub gh;
    private transient GHMyself me;
    private transient GithubSecurityRealm myRealm = null;

    public static final TimeUnit CACHE_EXPIRY = TimeUnit.HOURS;
    /**
     * Cache for faster organization based security
     */
    private static final Cache<String, Set<String>> userOrganizationCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private static final Cache<String, Set<String>> repositoriesByUserCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private static final Cache<String, GithubUser> usersByIdCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    /**
     * This cache is for repositories and is explicitly _not_ static because we
     * want to store repo information per-user (and this class should be per-user).
     * We potentially could hold a separe static cache for public repo info
     * that applies to all users, but it wouldn't be able to contain user-specific
     * details like exact permissions (read/write/admin).
     *
     * This representation of the repo holds details on whether the repo is
     * public/private, as well as whether the current user has pull/push/admin
     * access.
     */
    private final Cache<String, RepoRights> repositoryCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

    private static final GithubUser UNKNOWN_USER = new GithubUser(null);

    /** Wrappers for cache **/
    static class GithubUser {
        public final GHUser user;

        public GithubUser(GHUser user) {
            this.user = user;
        }
    }

    static class RepoRights {
        public final boolean hasAdminAccess;
        public final boolean hasPullAccess;
        public final boolean hasPushAccess;
        public final boolean isPrivate;

        public RepoRights(GHRepository repo) {
            if (repo != null) {
                this.hasAdminAccess = repo.hasAdminAccess();
                this.hasPullAccess = repo.hasPullAccess();
                this.hasPushAccess = repo.hasPushAccess();
                this.isPrivate = repo.isPrivate();
            } else {
                // assume null repo means we had no rights to view it
                // so must be private
                this.hasAdminAccess = false;
                this.hasPullAccess = false;
                this.hasPushAccess = false;
                this.isPrivate = true;
            }
        }

        public boolean hasAdminAccess() {
          return this.hasAdminAccess;
        }

        public boolean hasPullAccess() {
          return this.hasPullAccess;
        }

        public boolean hasPushAccess() {
          return this.hasPushAccess;
        }

        public boolean isPrivate() {
          return this.isPrivate;
        }
    }

    public GithubAuthenticationToken(final String accessToken, final String githubServer) throws IOException {
        super(new GrantedAuthority[] {});

        this.accessToken = accessToken;
        this.githubServer = githubServer;

        this.me = getGitHub().getMyself();
        assert this.me!=null;

        setAuthenticated(true);

        this.userName = this.me.getLogin();
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        if(jenkins.getSecurityRealm() instanceof GithubSecurityRealm) {
            if(myRealm == null) {
                myRealm = (GithubSecurityRealm) jenkins.getSecurityRealm();
            }
            //Search for scopes that allow fetching team membership.  This is documented online.
            //https://developer.github.com/v3/orgs/#list-your-organizations
            //https://developer.github.com/v3/orgs/teams/#list-user-teams
            if(myRealm.hasScope("read:org") || myRealm.hasScope("admin:org") || myRealm.hasScope("user") || myRealm.hasScope("repo")) {
                Map<String, GHOrganization> myOrgs = getGitHub().getMyOrganizations();
                Map<String, Set<GHTeam>> myTeams = getGitHub().getMyTeams();

                //fetch organization-only memberships (i.e.: groups without teams)
                for(String orgLogin : myOrgs.keySet()){
                    if(!myTeams.containsKey(orgLogin)){
                        myTeams.put(orgLogin, Collections.<GHTeam>emptySet());
                    }
                }

                for (Map.Entry<String, Set<GHTeam>> teamEntry : myTeams.entrySet()) {
                    String orgLogin = teamEntry.getKey();
                    LOGGER.log(Level.FINE, "Fetch teams for user " + userName + " in organization " + orgLogin);
                    authorities.add(new GrantedAuthorityImpl(orgLogin));
                    for (GHTeam team : teamEntry.getValue()) {
                        authorities.add(new GrantedAuthorityImpl(orgLogin + GithubOAuthGroupDetails.ORG_TEAM_SEPARATOR
                                + team.getName()));
                    }
                }
            }
        }
    }

    /**
     * Necessary for testing
     */
    public static void clearCaches() {
        userOrganizationCache.invalidateAll();
        repositoriesByUserCache.invalidateAll();
        usersByIdCache.invalidateAll();
    }

    /**
     * Gets the OAuth access token, so that it can be persisted and used elsewhere.
     * @return accessToken
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Gets the Github server used for this token
     * @return githubServer
     */
    public String getGithubServer() {
        return githubServer;
    }

    public GitHub getGitHub() throws IOException {
        if (this.gh == null) {

            String host;
            try {
                host = new URL(this.githubServer).getHost();
            } catch (MalformedURLException e) {
                throw new IOException("Invalid GitHub API URL: " + this.githubServer, e);
            }

            OkHttpClient client = new OkHttpClient().setProxy(getProxy(host));

            this.gh = GitHubBuilder.fromEnvironment()
                    .withEndpoint(this.githubServer)
                    .withOAuthToken(this.accessToken)
                    .withRateLimitHandler(RateLimitHandler.FAIL)
                    .withConnector(new OkHttpConnector(new OkUrlFactory(client)))
                    .build();
        }
        return gh;
    }

    /**
     * Uses proxy if configured on pluginManager/advanced page
     *
     * @param host GitHub's hostname to build proxy to
     *
     * @return proxy to use it in connector. Should not be null as it can lead to unexpected behaviour
     */
    @Nonnull
    private static Proxy getProxy(@Nonnull String host) {
        Jenkins jenkins = Jenkins.getInstance();

        if (jenkins.proxy == null) {
            return Proxy.NO_PROXY;
        } else {
            return jenkins.proxy.createProxy(host);
        }
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return authorities.toArray(new GrantedAuthority[authorities.size()]);
    }

    public Object getCredentials() {
        return ""; // do not expose the credential
    }

    /**
     * Returns the login name in GitHub.
     * @return principal
     */
    public String getPrincipal() {
        return this.userName;
    }

    /**
     * Returns the GHMyself object from this instance.
     * @return myself
     */
    public GHMyself getMyself() throws IOException {
        if (me == null) {
            me = getGitHub().getMyself();
        }
        return me;
    }

    /**
     * For some reason I can't get the github api to tell me for the current
     * user the groups to which he belongs.
     *
     * So this is a slightly larger consideration. If the authenticated user is
     * part of any team within the organization then they have permission.
     *
     * It caches user organizations for 24 hours for faster web navigation.
     *
     * @param candidateName name of the candidate
     * @param organization name of the organization
     * @return has organization permission
     */
    public boolean hasOrganizationPermission(String candidateName,
            String organization) {
        try {
            Set<String> v = userOrganizationCache.get(candidateName,new Callable<Set<String>>() {
                @Override
                public Set<String> call() throws Exception {
                    return getGitHub().getMyOrganizations().keySet();
                }
            });

            return v.contains(organization);
        } catch (ExecutionException e) {
            throw new RuntimeException("authorization failed for user = "
                    + candidateName, e);
        }
    }

    public boolean hasRepositoryPermission(String repositoryName, Permission permission) {
        LOGGER.log(Level.FINEST, "Checking for permission: " + permission + " on repo: " + repositoryName + " for user: " + this.userName);
        boolean isRepoOfMine = myRepositories().contains(repositoryName);
        if (isRepoOfMine) {
          return true;
        }
        // This is not my repository, nor is it a repository of an organization I belong to.
        // Check what rights I have on the github repo.
        RepoRights repository = loadRepository(repositoryName);
        if (repository == null) {
          return false;
        }
        // let admins do anything
        if (repository.hasAdminAccess()) {
          return true;
        }
        // WRITE or READ can Read/Build/View Workspace
        if (permission.equals(Item.READ) || permission.equals(Item.BUILD) || permission.equals(Item.WORKSPACE)) {
          return repository.hasPullAccess() || repository.hasPushAccess();
        }
        // WRITE can cancel builds or view config
        if (permission.equals(Item.CANCEL) || permission.equals(Item.EXTENDED_READ)) {
          return repository.hasPushAccess();
        }
        // Need ADMIN rights to do rest: configure, create, delete, discover, wipeout
        return false;
    }

    public Set<String> myRepositories() {
        try {
            return repositoriesByUserCache.get(getName(),
                new Callable<Set<String>>() {
                    @Override
                    public Set<String> call() throws Exception {
                        List<GHRepository> userRepositoryList = getMyself().listRepositories().asList();
                        Set<String> repositoryNames = listToNames(userRepositoryList);
                        GHPersonSet<GHOrganization> organizations = getMyself().getAllOrganizations();
                        for (GHOrganization organization : organizations) {
                            List<GHRepository> orgRepositoryList = organization.listRepositories().asList();
                            Set<String> orgRepositoryNames = listToNames(orgRepositoryList);
                            repositoryNames.addAll(orgRepositoryNames);
                        }
                        return repositoryNames;
                    }
                }
            );
        } catch (ExecutionException e) {
            LOGGER.log(Level.SEVERE, "an exception was thrown", e);
            throw new RuntimeException("authorization failed for user = "
                    + getName(), e);
        }
    }

    public Set<String> listToNames(Collection<GHRepository> respositories) throws IOException {
        Set<String> names = new HashSet<String>();
        for (GHRepository repository : respositories) {
            String ownerName = repository.getOwner().getLogin();
            String repoName = repository.getName();
            names.add(ownerName + "/" + repoName);
        }
        return names;
    }

    public boolean isPublicRepository(String repositoryName) {
        RepoRights repository = loadRepository(repositoryName);
        return repository != null && !repository.isPrivate();
    }

    private static final Logger LOGGER = Logger
            .getLogger(GithubAuthenticationToken.class.getName());

    public GHUser loadUser(String username) throws IOException {
        GithubUser user;
        try {
            user = usersByIdCache.getIfPresent(username);
            if (gh != null && user == null && isAuthenticated()) {
                GHUser ghUser = getGitHub().getUser(username);
                user = new GithubUser(ghUser);
                usersByIdCache.put(username, user);
            }
        } catch (IOException e) {
            LOGGER.log(Level.FINEST, e.getMessage(), e);
            user = UNKNOWN_USER;
            usersByIdCache.put(username, UNKNOWN_USER);
        }
        return user != null ? user.user : null;
    }

    public GHOrganization loadOrganization(String organization) {
        try {
            if (gh != null && isAuthenticated())
                return getGitHub().getOrganization(organization);
        } catch (IOException | RuntimeException e) {
            LOGGER.log(Level.FINEST, e.getMessage(), e);
        }
        return null;
    }

    public RepoRights loadRepository(final String repositoryName) {
      try {
          if (gh != null && isAuthenticated() && (myRealm.hasScope("repo") || myRealm.hasScope("public_repo"))) {
              return repositoryCache.get(repositoryName,
                  new Callable<RepoRights>() {
                      @Override
                      public RepoRights call() throws Exception {
                          GHRepository repo = getGitHub().getRepository(repositoryName);
                          return new RepoRights(repo);
                      }
                  }
              );
          }
      } catch (Exception e) {
          LOGGER.log(Level.SEVERE, "an exception was thrown", e);
          LOGGER.log(Level.WARNING,
              "Looks like a bad GitHub URL OR the Jenkins user {0} does not have access to the repository {1}. May need to add 'repo' or 'public_repo' to the list of oauth scopes requested.",
              new Object[] { this.userName, repositoryName });
      }
      return null;
    }

    public GHTeam loadTeam(String organization, String team) {
        try {
            GHOrganization org = loadOrganization(organization);
            if (org != null) {
                return org.getTeamByName(team);
            }
        } catch (IOException e) {
            LOGGER.log(Level.FINEST, e.getMessage(), e);
        }
        return null;
    }

    public GithubOAuthUserDetails getUserDetails(String username) throws IOException {
        GHUser user = loadUser(username);
        if (user != null) {
            return new GithubOAuthUserDetails(user.getLogin(), this);
        }
        return null;
    }
}
