package org.jenkinsci.plugins;

import jenkins.model.Jenkins;
import org.apache.commons.lang.SerializationUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.RateLimitHandler;
import org.kohsuke.github.extras.okhttp3.OkHttpGitHubConnector;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class GithubAuthenticationTokenTest {

    @Mock
    private GithubSecurityRealm securityRealm;

    @AfterEach
    void tearDown() {
        GithubAuthenticationToken.clearCaches();
    }

    private void mockJenkins(MockedStatic<Jenkins> mockedJenkins) {
        Jenkins jenkins = Mockito.mock(Jenkins.class);
        mockedJenkins.when(Jenkins::get).thenReturn(jenkins);
        Mockito.when(jenkins.getSecurityRealm()).thenReturn(securityRealm);
        Mockito.when(securityRealm.hasScope("read:org")).thenReturn(true);
    }

    @Test
    void testTokenSerialization() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            mockGHMyselfAs(mockedGitHubBuilder, "bob");
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");
            byte[] serializedToken = SerializationUtils.serialize(authenticationToken);
            GithubAuthenticationToken deserializedToken = (GithubAuthenticationToken) SerializationUtils.deserialize(serializedToken);
            assertEquals(deserializedToken.getAccessToken(), authenticationToken.getAccessToken());
            assertEquals(deserializedToken.getPrincipal(), authenticationToken.getPrincipal());
            assertEquals(deserializedToken.getGithubServer(), authenticationToken.getGithubServer());
            assertEquals(deserializedToken.getMyself().getLogin(), authenticationToken.getMyself().getLogin());
        }
    }

    private static GHMyself mockGHMyselfAs(MockedStatic<GitHubBuilder> mockedGitHubBuilder, String username) throws IOException {
        GitHub gh = Mockito.mock(GitHub.class);
        GitHubBuilder builder = Mockito.mock(GitHubBuilder.class);
        mockedGitHubBuilder.when(GitHubBuilder::fromEnvironment).thenReturn(builder);
        Mockito.when(builder.withEndpoint("https://api.github.com")).thenReturn(builder);
        Mockito.when(builder.withOAuthToken("accessToken")).thenReturn(builder);
        Mockito.when(builder.withRateLimitHandler(RateLimitHandler.FAIL)).thenReturn(builder);
        Mockito.when(builder.withConnector(Mockito.any(OkHttpGitHubConnector.class))).thenReturn(builder);
        Mockito.when(builder.build()).thenReturn(gh);
        GHMyself me = Mockito.mock(GHMyself.class);
        Mockito.when(gh.getMyself()).thenReturn(me);
        Mockito.when(me.getLogin()).thenReturn(username);
        return me;
    }
}
