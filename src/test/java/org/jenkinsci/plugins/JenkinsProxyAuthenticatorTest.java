package org.jenkinsci.plugins;

import hudson.ProxyConfiguration;
import okhttp3.Credentials;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Assert;
import org.junit.Test;


public class JenkinsProxyAuthenticatorTest {


    @Test
    public void refusesChallengeIfAuthenticationAlreadyFailed() {
        Request previousRequest =
                new Request.Builder()
                        .url("https://example.com")
                        .header("Proxy-Authorization", "notNull")
                        .build();

        Response response =
                new Response.Builder()
                        .code(407)
                        .request(previousRequest)
                        .protocol(Protocol.HTTP_1_0)
                        .message("Unauthorized")
                        .build();

        Assert.assertNull(new JenkinsProxyAuthenticator(null).authenticate(null, response));
    }

    @Test
    public void refusesPreemptiveOkHttpChallenge() {
        Request previousRequest = new Request.Builder().url("https://example.com").build();

        Response response =
                new Response.Builder()
                        .request(previousRequest)
                        .header("Proxy-Authenticate", "OkHttp-Preemptive")
                        .code(407)
                        .protocol(Protocol.HTTP_1_0)
                        .message("Unauthorized")
                        .build();

        Assert.assertNull(new JenkinsProxyAuthenticator(null).authenticate(null, response));
    }

    @Test
    public void acceptsBasicChallenge() {
        Request previousRequest = new Request.Builder().url("https://example.com").build();

        Response response =
                new Response.Builder()
                        .request(previousRequest)
                        .header("Proxy-Authenticate", "Basic")
                        .code(407)
                        .protocol(Protocol.HTTP_1_0)
                        .message("Unauthorized")
                        .build();

        ProxyConfiguration proxyConfiguration =
                new ProxyConfiguration("proxy", 80, "user", "password");
        String credentials = Credentials.basic("user", "password");
        Request requestWithBasicAuth =
                new JenkinsProxyAuthenticator(proxyConfiguration).authenticate(null, response);

        Assert.assertEquals(requestWithBasicAuth.header("Proxy-Authorization"), credentials);
    }

    @Test
    public void refusesAnyChallengeWhichIsNotBasicAuthentication() {
        Request previousRequest = new Request.Builder().url("https://example.com").build();

        Response response =
                new Response.Builder()
                        .request(previousRequest)
                        .code(407)
                        .protocol(Protocol.HTTP_1_0)
                        .header("Proxy-Authenticate", "Digest")
                        .message("Unauthorized")
                        .build();

        Assert.assertNull(new JenkinsProxyAuthenticator(null).authenticate(null, response));
    }

}
