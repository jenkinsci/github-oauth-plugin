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

import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.HashSet;
import java.util.logging.Logger;
import java.util.logging.Level;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import hudson.security.SecurityRealm;
import java.util.Collection;
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

	private final String userName;
	private final GitHub gh;
        private final GHMyself me;
	
	/**
	 * Cache for faster organization based security 
	 */
	private static final Cache<String, Set<String>> userOrganizationCache =
            CacheBuilder.newBuilder().expireAfterWrite(1,TimeUnit.HOURS).build();

	private static final Cache<String, Set<String>> repositoryCollaboratorsCache =
            CacheBuilder.newBuilder().expireAfterWrite(1,TimeUnit.HOURS).build();

	private static final Cache<String, Set<String>> repositoriesByUserCache =
            CacheBuilder.newBuilder().expireAfterWrite(1,TimeUnit.HOURS).build();

	private static final Cache<String, Boolean> publicRepositoryCache =
            CacheBuilder.newBuilder().expireAfterWrite(1,TimeUnit.HOURS).build();

    private final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

	public GithubAuthenticationToken(String accessToken, String githubServer) throws IOException {

		super(new GrantedAuthority[] {});

		this.accessToken = accessToken;
        this.gh = GitHub.connectUsingOAuth(githubServer, accessToken);

        this.me = gh.getMyself();
        assert this.me!=null;

        setAuthenticated(true);

        this.userName = this.me.getLogin();
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        for (String name : gh.getMyOrganizations().keySet())
            authorities.add(new GrantedAuthorityImpl(name));
	}

        /**
         * Necessary for testing
         */
        public static void clearCaches() {
            userOrganizationCache.invalidateAll();
            repositoryCollaboratorsCache.invalidateAll();
            repositoriesByUserCache.invalidateAll();
        }

    /**
     * Gets the OAuth access token, so that it can be persisted and used elsewhere.
     */
    public String getAccessToken() {
        return accessToken;
    }

    public GitHub getGitHub() {
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
     */
	public String getPrincipal() {
		return this.userName;
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
	 * @param candidateName
	 * @param organization
	 * @return
	 */
	public boolean hasOrganizationPermission(String candidateName,
			String organization) {

		try {
            Set<String> v = userOrganizationCache.get(candidateName,new Callable<Set<String>>() {
                @Override
                public Set<String> call() throws Exception {
                    return gh.getMyOrganizations().keySet();
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
            Set<String> myRepositories = repositoriesByUserCache.get(getName(),
                new Callable<Set<String>>() {
                    @Override
                    public Set<String> call() throws Exception {
                        List<GHRepository> userRepositoryList = me.listRepositories().asList();
                        Set<String> repositoryNames = listToNames(userRepositoryList);
                        GHPersonSet<GHOrganization> organizations = me.getAllOrganizations();
                        for (GHOrganization organization : organizations) {
                            List<GHRepository> orgRepositoryList = organization.listRepositories().asList();
                            Set<String> orgRepositoryNames = listToNames(orgRepositoryList);
                            repositoryNames.addAll(orgRepositoryNames);
                        }
                        return repositoryNames;
                    }
                }
            );

            return myRepositories;
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
            Boolean isPublic = publicRepositoryCache.get(repositoryName,
                new Callable<Boolean>() {
                    @Override
                    public Boolean call() throws Exception {
                        GHRepository repository = loadRepository(repositoryName);
                        if (repository == null) {
                            // We don't have access so it must not be public (it could be non-existant)
                            return Boolean.FALSE;
                        } else {
                            return new Boolean(!repository.isPrivate());
                        }
                    }
                }
            );

            return isPublic.booleanValue();
        } catch (ExecutionException e) {
            LOGGER.log(Level.SEVERE, "an exception was thrown", e);
            throw new RuntimeException("authorization failed for user = "
                        + getName(), e);
        }
    }

	private static final Logger LOGGER = Logger
			.getLogger(GithubAuthenticationToken.class.getName());

	public GHUser loadUser(String username) throws IOException {
		if (gh != null && isAuthenticated())
			return gh.getUser(username);
		else
			return null;
	}

	public GHOrganization loadOrganization(String organization)
			throws IOException {

		if (gh != null && isAuthenticated())
			return gh.getOrganization(organization);
		else
			return null;

	}

	public GHRepository loadRepository(String repositoryName) {
            try {
                if (gh != null && isAuthenticated()) {
                    return gh.getRepository(repositoryName);
                } else {
                    return null;
                }
            } catch(FileNotFoundException e) {
                LOGGER.log(Level.WARNING, "Looks like a bad github URL OR the Jenkins user does not have access to the repository{0}", repositoryName);
                return null;
            } catch(IOException e) {
                LOGGER.log(Level.WARNING, "Looks like a bad github URL OR the Jenkins user does not have access to the repository{0}", repositoryName);
                return null;
            }
	}

	public GHTeam loadTeam(String organization, String team) throws IOException {
		if (gh != null && isAuthenticated()) {

			GHOrganization org = gh.getOrganization(organization);

			if (org != null) {
				Map<String, GHTeam> teamMap = org.getTeams();

				return teamMap.get(team);
			} else
				return null;

		} else
			return null;
	}
}
