package org.jenkinsci.plugins;

import jenkins.model.Jenkins;
import org.apache.commons.lang.SerializationUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.RateLimitHandler;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

@RunWith(PowerMockRunner.class)
@PrepareForTest({GitHub.class, GitHubBuilder.class, Jenkins.class, GithubSecurityRealm.class})
public class GithubAuthenticationTokenTest {

    @Mock
    private Jenkins jenkins;

    @Mock
    private GithubSecurityRealm securityRealm;

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

    @After
    public void after() {
        GithubAuthenticationToken.clearCaches();
    }

    private GHMyself mockGHMyselfAs(String username) throws IOException {
        GitHub gh = PowerMockito.mock(GitHub.class);
        GitHubBuilder builder = PowerMockito.mock(GitHubBuilder.class);
        PowerMockito.mockStatic(GitHub.class);
        PowerMockito.mockStatic(GitHubBuilder.class);
        PowerMockito.when(GitHubBuilder.fromEnvironment()).thenReturn(builder);
        PowerMockito.when(builder.withEndpoint("https://api.github.com")).thenReturn(builder);
        PowerMockito.when(builder.withOAuthToken("accessToken")).thenReturn(builder);
        PowerMockito.when(builder.withRateLimitHandler(RateLimitHandler.FAIL)).thenReturn(builder);
        PowerMockito.when(builder.build()).thenReturn(gh);
        GHMyself me = PowerMockito.mock(GHMyself.class);
        PowerMockito.when(gh.getMyself()).thenReturn(me);
        PowerMockito.when(me.getLogin()).thenReturn(username);
        return me;
    }

}
