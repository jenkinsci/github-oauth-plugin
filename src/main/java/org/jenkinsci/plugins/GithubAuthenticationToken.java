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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import hudson.security.SecurityRealm;
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

import java.io.IOException;
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

    private static final Cache<String, Set<String>> repositoryCollaboratorsCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private static final Cache<String, Set<String>> repositoriesByUserCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private static final Cache<String, Boolean> publicRepositoryCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private static final Cache<String, GithubUser> usersByIdCache =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

    private final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

    private static final GithubUser UNKNOWN_USER = new GithubUser(null);

    /** Wrapper for cache **/
    static class GithubUser {
        public final GHUser user;

        public GithubUser(GHUser user) {
            this.user = user;
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
        repositoryCollaboratorsCache.invalidateAll();
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
            this.gh = GitHubBuilder.fromEnvironment()
                    .withEndpoint(this.githubServer)
                    .withOAuthToken(this.accessToken)
                    .withRateLimitHandler(RateLimitHandler.FAIL)
                    .build();
        }
        return gh;
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

    public boolean hasRepositoryPermission(final String repositoryName) {
        return myRepositories().contains(repositoryName);
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

    public boolean isPublicRepository(final String repositoryName) {
        try {
            return publicRepositoryCache.get(repositoryName,
                new Callable<Boolean>() {
                    @Override
                    public Boolean call() throws Exception {
                        GHRepository repository = loadRepository(repositoryName);
                        // We don't have access so it must not be public (it could be non-existant)
                        return repository != null && !repository.isPrivate();
                    }
                }
            );
        } catch (ExecutionException e) {
            LOGGER.log(Level.SEVERE, "an exception was thrown", e);
            throw new RuntimeException("authorization failed for user = "
                    + getName(), e);
        }
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

    public GHRepository loadRepository(String repositoryName) {
        try {
            if (gh != null && isAuthenticated()) {
                return getGitHub().getRepository(repositoryName);
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING,
                    "Looks like a bad GitHub URL OR the Jenkins user does not have access to the repository{0}",
                    repositoryName);
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

    public GrantedAuthority[] getGrantedAuthorities(GHUser user) {
        List<GrantedAuthority> groups = new ArrayList<GrantedAuthority>();
        try {
            GHPersonSet<GHOrganization> orgs;
            if(myRealm == null) {
                Jenkins jenkins = Jenkins.getInstance();
                if (jenkins == null) {
                    throw new IllegalStateException("Jenkins not started");
                }
                myRealm = (GithubSecurityRealm) jenkins.getSecurityRealm();
            }
            //Search for scopes that allow fetching team membership.  This is documented online.
            //https://developer.github.com/v3/orgs/#list-your-organizations
            //https://developer.github.com/v3/orgs/teams/#list-user-teams
            if(this.userName.equals(user.getLogin()) && (myRealm.hasScope("read:org") || myRealm.hasScope("admin:org") || myRealm.hasScope("user") || myRealm.hasScope("repo"))) {
                //This allows us to search for private organization membership.
                orgs = getMyself().getAllOrganizations();
            } else {
                //This searches for public organization membership.
                orgs = user.getOrganizations();
            }
            for (GHOrganization ghOrganization : orgs) {
                String orgLogin = ghOrganization.getLogin();
                LOGGER.log(Level.FINE, "Fetch teams for user " + user.getLogin() + " in organization " + orgLogin);
                groups.add(new GrantedAuthorityImpl(orgLogin));
                try {
                    if (!getMyself().isMemberOf(ghOrganization)) {
                        continue;
                    }
                    Map<String, GHTeam> teams = ghOrganization.getTeams();
                    for (Map.Entry<String, GHTeam> entry : teams.entrySet()) {
                        GHTeam team = entry.getValue();
                        if (team.hasMember(user)) {
                            groups.add(new GrantedAuthorityImpl(orgLogin + GithubOAuthGroupDetails.ORG_TEAM_SEPARATOR
                                    + team));
                        }
                    }
                } catch (IOException | Error ignore) {
                    LOGGER.log(Level.FINEST, "not enough rights to list teams from " + orgLogin, ignore);
                }
            }
        } catch(IOException e) {
            LOGGER.log(Level.FINE, e.getMessage(), e);
        }
        return groups.toArray(new GrantedAuthority[groups.size()]);
    }
}
