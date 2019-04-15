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
import javax.annotation.Nullable;


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

    /**
     * This is a double-layered cached. The first mapping is from github username
     * to a secondary cache of repositories. This is so we can mass populate
     * the initial set of repos a user is a collaborator on at once.
     *
     * The secondary layer is from repository names (full names) to rights the
     * user has for that repo. Here we may add single entries occasionally, and this
     * is primarily about adding entries for public repos that they're not explicitly
     * a collaborator on (or updating a given repo's entry)
     *
     * We could make this a single layer since this token object should be per-user,
     * but I'm unsure of how long it actually lives in memory.
     */
    private static final Cache<String, Cache<String, RepoRights>> repositoriesByUserCache =
            CacheBuilder.newBuilder().expireAfterWrite(24, CACHE_EXPIRY).build();

    /**
     * Here we keep a global cache of whether repos are public or private, since that
     * can be shared across users (and public repos are global read/pull, so we
     * can avoid asking for user repos if the repo is known to be public and they want read rights)
     */
    private static final Cache<String, Boolean> repositoriesPublicStatusCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private static final Cache<String, GithubUser> usersByIdCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private static final Cache<String, GithubMyself> usersByTokenCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.MINUTES).build();

    private static final Cache<String, Map<String, Set<GHTeam>>> userTeamsCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

    private static final GithubUser UNKNOWN_USER = new GithubUser(null);
    private static final GithubMyself UNKNOWN_TOKEN = new GithubMyself(null);

    /** Wrappers for cache **/
    static class GithubUser {
        public final GHUser user;

        public GithubUser(GHUser user) {
            this.user = user;
        }
    }

    static class GithubMyself {
        public final GHMyself me;

        public GithubMyself(GHMyself me) {
            this.me = me;
        }
    }

    static class RepoRights {
        public final boolean hasAdminAccess;
        public final boolean hasPullAccess;
        public final boolean hasPushAccess;
        public final boolean isPrivate;

        public RepoRights(@Nullable GHRepository repo) {
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

        this.me = loadMyself(accessToken);

        assert this.me!=null;

        setAuthenticated(true);

        this.userName = this.me.getLogin();

        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

        // This stuff only really seems useful if *not* using GithubAuthorizationStrategy
        // but instead using matrix so org/team can be granted rights
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        if (jenkins.getSecurityRealm() instanceof GithubSecurityRealm) {
            if (myRealm == null) {
                myRealm = (GithubSecurityRealm) jenkins.getSecurityRealm();
            }
            // Search for scopes that allow fetching team membership.  This is documented online.
            // https://developer.github.com/v3/orgs/#list-your-organizations
            // https://developer.github.com/v3/orgs/teams/#list-user-teams
            if (myRealm.hasScope("read:org") || myRealm.hasScope("admin:org") || myRealm.hasScope("user") || myRealm.hasScope("repo")) {
                try {
                    Set<String> myOrgs = getUserOrgs();

                    Map<String, Set<GHTeam>> myTeams = userTeamsCache.get(this.userName, new Callable<Map<String, Set<GHTeam>>>() {
                        @Override
                        public Map<String, Set<GHTeam>> call() throws Exception {
                            return getGitHub().getMyTeams();
                        }
                    });

                    // fetch organization-only memberships (i.e.: groups without teams)
                    for (String orgLogin : myOrgs) {
                        if (!myTeams.containsKey(orgLogin)) {
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
                } catch (ExecutionException e) {
                    throw new RuntimeException("authorization failed for user = "
                            + this.userName, e);
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
        repositoriesPublicStatusCache.invalidateAll();
        usersByIdCache.invalidateAll();
        usersByTokenCache.invalidateAll();
        userTeamsCache.invalidateAll();
    }

    /**
     * Gets the OAuth access token, so that it can be persisted and used elsewhere.
     * @return accessToken
     */
    String getAccessToken() {
        return accessToken;
    }

    /**
     * Gets the Github server used for this token
     * @return githubServer
     */
    String getGithubServer() {
        return githubServer;
    }

    GitHub getGitHub() throws IOException {
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

    @Override
    public Object getCredentials() {
        return ""; // do not expose the credential
    }

    /**
     * Returns the login name in GitHub.
     * @return principal
     */
    @Override
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
     * Wraps grabbing a user's github orgs with our caching
     * @return                    the Set of org names current user is a member of
     * @throws ExecutionException if the api call somehow blows up when lazy loading
     */
    @Nonnull
    private Set<String> getUserOrgs() throws ExecutionException {
        return userOrganizationCache.get(this.userName, new Callable<Set<String>>() {
            @Override
            public Set<String> call() throws Exception {
                return getGitHub().getMyOrganizations().keySet();
            }
        });
    }

    @Nonnull
    boolean isMemberOfAnyOrganizationInList(@Nonnull Collection<String> organizations) {
        try {
            Set<String> userOrgs = getUserOrgs();
            for (String orgName : organizations) {
              if (userOrgs.contains(orgName)) {
                return true;
              }
            }
            return false;
        } catch (ExecutionException e) {
            throw new RuntimeException("authorization failed for user = "
                    + this.userName, e);
        }
    }

    @Nonnull
    boolean hasRepositoryPermission(@Nonnull String repositoryName, @Nonnull Permission permission) {
        LOGGER.log(Level.FINEST, "Checking for permission: " + permission + " on repo: " + repositoryName + " for user: " + this.userName);
        boolean isReadPermission = isReadRelatedPermission(permission);
        if (isReadPermission) {
          // here we do a 2-pass system since public repos are global read, so if *any* user has retrieved tha info
          // for the repo, we can use it here to possibly skip loading the full repo details for the user.
          Boolean isPublic = repositoriesPublicStatusCache.getIfPresent(repositoryName);
          if (isPublic != null && isPublic.booleanValue()) {
            return true;
          }
        }
        // repo is not public (or we don't yet know) so load it up...
        RepoRights repository = loadRepository(repositoryName);
        // let admins do anything
        if (repository.hasAdminAccess()) {
          return true;
        }
        // WRITE or READ (or public repo) can Read/Build/View Workspace
        if (isReadPermission) {
          return !repository.isPrivate() || repository.hasPullAccess() || repository.hasPushAccess();
        }
        // WRITE can cancel builds or view config
        if (permission.equals(Item.CANCEL) || permission.equals(Item.EXTENDED_READ)) {
          return repository.hasPushAccess();
        }
        // Need ADMIN rights to do rest: configure, create, delete, wipeout
        return false;
    }

    @Nonnull
    private boolean isReadRelatedPermission(@Nonnull Permission permission) {
      return permission.equals(Item.DISCOVER) ||
             permission.equals(Item.READ) ||
             permission.equals(Item.BUILD) ||
             permission.equals(Item.WORKSPACE);
    }

    /**
     * Returns a mapping from repo names to repo rights for the current user
     * @return [description]
     */
    @Nonnull
    private Cache<String, RepoRights> myRepositories() {
        try {
            return repositoriesByUserCache.get(this.userName,
                new Callable<Cache<String, RepoRights>>() {
                    @Override
                    public Cache<String, RepoRights> call() throws Exception {
                        // listRepositories returns all repos owned by user, where they are a collaborator,
                        //  and any user has access through org membership
                        List<GHRepository> userRepositoryList = getMyself().listRepositories(100).asList(); // use max page size of 100 to limit API calls
                        // Now we want to cache each repo's rights too
                        Cache<String, RepoRights> repoNameToRightsCache =
                                CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();
                        for (GHRepository repo : userRepositoryList) {
                          RepoRights rights = new RepoRights(repo);
                          String repositoryName = repo.getFullName();
                          // store in user's repo cache
                          repoNameToRightsCache.put(repositoryName, rights);
                          // store public/private flag in our global cache
                          repositoriesPublicStatusCache.put(repositoryName, !rights.isPrivate());
                        }
                        return repoNameToRightsCache;
                    }
                }
            );
        } catch (ExecutionException e) {
            LOGGER.log(Level.SEVERE, "an exception was thrown", e);
            throw new RuntimeException("authorization failed for user = "
                    + this.userName, e);
        }
    }

    private static final Logger LOGGER = Logger
            .getLogger(GithubAuthenticationToken.class.getName());

    @Nullable
    GHUser loadUser(@Nonnull String username) throws IOException {
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

    private GHMyself loadMyself(@Nonnull String token) throws IOException {
        GithubMyself me;
        try {
            me = usersByTokenCache.getIfPresent(token);
            if (me == null) {
                GHMyself ghMyself = getGitHub().getMyself();
                me = new GithubMyself(ghMyself);
                usersByTokenCache.put(token, me);
                // Also stick into usersByIdCache (to have latest copy)
                String username = ghMyself.getLogin();
                usersByIdCache.put(username, new GithubUser(ghMyself));
            }
        } catch (IOException e) {
            LOGGER.log(Level.FINEST, e.getMessage(), e);
            me = UNKNOWN_TOKEN;
            usersByTokenCache.put(token, UNKNOWN_TOKEN);
        }
        return me.me;
    }

    @Nullable
    GHOrganization loadOrganization(@Nonnull String organization) {
        try {
            if (gh != null && isAuthenticated())
                return getGitHub().getOrganization(organization);
        } catch (IOException | RuntimeException e) {
            LOGGER.log(Level.FINEST, e.getMessage(), e);
        }
        return null;
    }

    @Nonnull
    private RepoRights loadRepository(@Nonnull final String repositoryName) {
      try {
          if (gh != null && isAuthenticated() && (myRealm.hasScope("repo") || myRealm.hasScope("public_repo"))) {
              Cache<String, RepoRights> repoNameToRightsCache = myRepositories();
              return repoNameToRightsCache.get(repositoryName,
                new Callable<RepoRights>() {
                    @Override
                    public RepoRights call() throws Exception {
                        GHRepository repo = getGitHub().getRepository(repositoryName);
                        RepoRights rights = new RepoRights(repo);
                        // store public/private flag in our cache
                        repositoriesPublicStatusCache.put(repositoryName, !rights.isPrivate());
                        return rights;
                    }
                }
              );
          }
      } catch (Exception e) {
          LOGGER.log(Level.FINEST, "an exception was thrown", e);
          LOGGER.log(Level.FINEST,
              "Looks like a bad GitHub URL OR the Jenkins user {0} does not have access to the repository {1}. May need to add 'repo' or 'public_repo' to the list of oauth scopes requested.",
              new Object[] { this.userName, repositoryName });
      }
      return new RepoRights(null); // treat as a private repo
    }

    @Nullable
    GHTeam loadTeam(@Nonnull String organization, @Nonnull String team) {
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

    @Nullable
    GithubOAuthUserDetails getUserDetails(@Nonnull String username) throws IOException {
        GHUser user = loadUser(username);
        if (user != null) {
            return new GithubOAuthUserDetails(user.getLogin(), this);
        }
        return null;
    }
}
