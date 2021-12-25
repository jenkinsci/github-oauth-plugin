package org.jenkinsci.plugins;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ProxyConfiguration;
import hudson.util.Secret;
import java.util.logging.Level;
import java.util.logging.Logger;
import okhttp3.Authenticator;
import okhttp3.Challenge;
import okhttp3.Credentials;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

public class JenkinsProxyAuthenticator implements Authenticator {


    private static final Logger LOGGER =
            Logger.getLogger(JenkinsProxyAuthenticator.class.getName());

    private final ProxyConfiguration proxy;

    public JenkinsProxyAuthenticator(ProxyConfiguration proxy) {
        this.proxy = proxy;
    }

    @CheckForNull
    @Override
    public Request authenticate(@CheckForNull Route route, @NonNull Response response) {

        if (response.request().header("Proxy-Authorization") != null) {
            return null; // Give up since we already tried to authenticate
        }

        if (response.challenges().isEmpty()) {
            // Proxy does not require authentication
            return null;
        }

        // Refuse pre-emptive challenge
        if (response.challenges().size() == 1) {
            Challenge challenge = response.challenges().get(0);
            if (challenge.scheme().equalsIgnoreCase("OkHttp-Preemptive")) {
                return null;
            }
        }

        for (Challenge challenge : response.challenges()) {
            if (challenge.scheme().equalsIgnoreCase("Basic")) {
                String username = proxy.getUserName();
                Secret password = proxy.getSecretPassword();
                if (username != null && password != null) {
                    String credentials = Credentials.basic(username, password.getPlainText());
                    return response.request()
                            .newBuilder()
                            .header("Proxy-Authorization", credentials)
                            .build();
                } else {
                    LOGGER.log(
                            Level.WARNING,
                            "Proxy requires Basic authentication but no username and password have been configured for the proxy");
                }
                break;
            }
        }

        LOGGER.log(
                Level.WARNING,
                "Proxy requires authentication, but does not support Basic authentication");
        return null;
    }
}
