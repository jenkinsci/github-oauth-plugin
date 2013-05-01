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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

import hudson.security.SecurityRealm;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.AbstractAuthenticationToken;
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

	private final String userName;
	private final GitHub gh;
	
	/**
	 * Cache for faster organization based security 
	 */
	private static final ConcurrentMap<String, Set<String>> userOrganizationCache = 
			new ConcurrentHashMap<String, Set<String>>();
	
	/**
	 * System time in millis when organization cache was las cleared
	 */
	private static long userOrganizationClearTime = System.currentTimeMillis();
	
	/**
	 * Organization cache timeout in milliseconds
	 */
	private static final int GITHUB_ORGANIZATION_CACHE_TIMEOUT = TimeUnit.HOURS.toMillis(24);

    private final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

	public GithubAuthenticationToken(String accessToken, String githubServer) throws IOException {

		super(new GrantedAuthority[] {});

		this.accessToken = accessToken;
        this.gh = GitHub.connectUsingOAuth(githubServer, accessToken);

        GHUser me = gh.getMyself();
        assert me!=null;

        setAuthenticated(true);

        this.userName = me.getLogin();
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        for (String name : gh.getMyOrganizations().keySet())
            authorities.add(new GrantedAuthorityImpl(name));
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
			
			if (System.currentTimeMillis() - GITHUB_ORGANIZATION_CACHE_TIMEOUT 
					> userOrganizationClearTime) {
				userOrganizationCache.clear();
				userOrganizationClearTime = System.currentTimeMillis();
			}
			
			if (!userOrganizationCache.containsKey(candidateName)) {
				userOrganizationCache.put(candidateName, 
						gh.getMyOrganizations().keySet());
			}
			
			if (userOrganizationCache.get(candidateName).contains(organization))
				return true;

			return false;

		} catch (IOException e) {

			throw new RuntimeException("authorization failed for user = "
					+ candidateName, e);

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
