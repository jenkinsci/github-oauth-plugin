package org.jenkinsci.plugins;

import jenkins.model.Jenkins;
import org.apache.commons.lang.SerializationUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHObject;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.RateLimitHandler;
import org.kohsuke.github.extras.OkHttpConnector;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(PowerMockRunner.class)
@PrepareForTest({GitHub.class, GitHubBuilder.class, Jenkins.class, GithubSecurityRealm.class})
public class GithubAuthenticationTokenTest {

    @Mock
    private Jenkins jenkins;

    @Mock
    private GithubSecurityRealm securityRealm;

    @Mock
    private GitHub gh;

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(Jenkins.class);
        PowerMockito.when(Jenkins.getInstance()).thenReturn(jenkins);
        PowerMockito.when(jenkins.getSecurityRealm()).thenReturn(securityRealm);
        PowerMockito.when(securityRealm.getOauthScopes()).thenReturn("read:org");
    }

    @Test
    public void testTokenSerialization() throws IOException {
        mockGHMyselfAs("bob");
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");
        byte[] serializedToken = SerializationUtils.serialize(authenticationToken);
        GithubAuthenticationToken deserializedToken = (GithubAuthenticationToken) SerializationUtils.deserialize(serializedToken);
        assertEquals(deserializedToken.getAccessToken(), authenticationToken.getAccessToken());
        assertEquals(deserializedToken.getPrincipal(), authenticationToken.getPrincipal());
        assertEquals(deserializedToken.getGithubServer(), authenticationToken.getGithubServer());
        assertEquals(deserializedToken.getMyself().getLogin(), deserializedToken.getMyself().getLogin());
    }

    private void mockAuthorizedOrgs(String org) {
        Set<String> authorizedOrgs = new HashSet<>(Arrays.asList(org));
        PowerMockito.when(this.securityRealm.getAuthorizedOrganizations()).thenReturn(authorizedOrgs);
        PowerMockito.when(this.securityRealm.hasScope("user")).thenReturn(true);
    }

    private void mockAsInOrg(String org) throws IOException {
        Map<String, GHOrganization> myOrgs = new HashMap<>();
        myOrgs.put(org, new GHOrganization());
        PowerMockito.when(this.gh.getMyOrganizations()).thenReturn(myOrgs);
    }

    @Test
    public void testInAuthorizedOrgs() throws IOException {
        mockGHMyselfAs("bob");
        mockAuthorizedOrgs("orgA");
        mockAsInOrg("orgA");

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");
        assertTrue(authenticationToken.isAuthenticated());
    }

    @Test
    public void testNotInAuthorizedOrgs() throws IOException {
        mockGHMyselfAs("bob");
        mockAuthorizedOrgs("orgA");
        mockAsInOrg("orgB");

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");
        assertFalse(authenticationToken.isAuthenticated());
    }

    @After
    public void after() {
        GithubAuthenticationToken.clearCaches();
    }

    private GHMyself mockGHMyselfAs(String username) throws IOException {
        GitHubBuilder builder = PowerMockito.mock(GitHubBuilder.class);
        PowerMockito.mockStatic(GitHub.class);
        PowerMockito.mockStatic(GitHubBuilder.class);
        PowerMockito.when(GitHubBuilder.fromEnvironment()).thenReturn(builder);
        PowerMockito.when(builder.withEndpoint("https://api.github.com")).thenReturn(builder);
        PowerMockito.when(builder.withOAuthToken("accessToken")).thenReturn(builder);
        PowerMockito.when(builder.withRateLimitHandler(RateLimitHandler.FAIL)).thenReturn(builder);
        PowerMockito.when(builder.withConnector(Mockito.any(OkHttpConnector.class))).thenReturn(builder);
        PowerMockito.when(builder.build()).thenReturn(this.gh);
        GHMyself me = PowerMockito.mock(GHMyself.class);
        PowerMockito.when(gh.getMyself()).thenReturn(me);
        PowerMockito.when(me.getLogin()).thenReturn(username);
        return me;
    }

}
