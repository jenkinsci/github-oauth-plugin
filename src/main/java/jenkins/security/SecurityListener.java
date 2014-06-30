package jenkins.security;

import hudson.ExtensionPoint;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class is a as is copy of jenkins.security.SecurityListener in jenkins core.
 * That class was is available for external security implementations in version > 1.569
 * This class would be deleted when code from 1.569 goes into a LTS release which this plugin can depend on.
 */
public abstract class SecurityListener implements ExtensionPoint {

    private static final Logger LOGGER = Logger.getLogger(SecurityListener.class.getName());

    /**
     * Fired when a user was successfully authenticated by password.
     * This might be via the web UI, or via REST (not with an API token) or CLI (not with an SSH key).
     * Only {@link AbstractPasswordBasedSecurityRealm}s are considered.
     *
     * @param details details of the newly authenticated user, such as name and groups
     */
    protected abstract void authenticated(@Nonnull UserDetails details);

    /**
     * Fired when a user tried to authenticate by password but failed.
     *
     * @param username the user
     * @see #authenticated
     */
    protected abstract void failedToAuthenticate(@Nonnull String username);

    /**
     * Fired when a user has logged in via the web UI.
     * Would be called after {@link #authenticated}.
     *
     * @param username the user
     */
    protected abstract void loggedIn(@Nonnull String username);

    /**
     * Fired when a user has failed to log in via the web UI.
     * Would be called after {@link #failedToAuthenticate}.
     *
     * @param username the user
     */
    protected abstract void failedToLogIn(@Nonnull String username);

    /**
     * Fired when a user logs out.
     *
     * @param username the user
     */
    protected abstract void loggedOut(@Nonnull String username);

    // TODO event for authenticated via SSH key in CLI (SshCliAuthenticator)
    // TODO event for authenticated via API token (ApiTokenFilter)
    // TODO event for permission denied exception thrown (mainly ACL.checkPermission), and/or caught at top level (ExceptionTranslationFilter.handleException)
    // TODO event for new user signed up (e.g. in HudsonPrivateSecurityRealm)
    // TODO event for CAPTCHA failure

    @Restricted(NoExternalUse.class)
    public static void fireAuthenticated(@Nonnull UserDetails details) {
        if (LOGGER.isLoggable(Level.FINE)) {
            List<String> groups = new ArrayList<String>();
            for (GrantedAuthority auth : details.getAuthorities()) {
                if (!auth.equals(SecurityRealm.AUTHENTICATED_AUTHORITY)) {
                    groups.add(auth.getAuthority());
                }
            }
            LOGGER.log(Level.FINE, "authenticated: {0} {1}", new Object[]{details.getUsername(), groups});
        }
        for (SecurityListener l : all()) {
            l.authenticated(details);
        }
    }

    @Restricted(NoExternalUse.class)
    public static void fireFailedToAuthenticate(@Nonnull String username) {
        LOGGER.log(Level.FINE, "failed to authenticate: {0}", username);
        for (SecurityListener l : all()) {
            l.failedToAuthenticate(username);
        }
    }

    @Restricted(NoExternalUse.class)
    public static void fireLoggedIn(@Nonnull String username) {
        LOGGER.log(Level.FINE, "logged in: {0}", username);
        for (SecurityListener l : all()) {
            l.loggedIn(username);
        }
    }

    @Restricted(NoExternalUse.class)
    public static void fireFailedToLogIn(@Nonnull String username) {
        LOGGER.log(Level.FINE, "failed to log in: {0}", username);
        for (SecurityListener l : all()) {
            l.failedToLogIn(username);
        }
    }

    @Restricted(NoExternalUse.class)
    public static void fireLoggedOut(@Nonnull String username) {
        LOGGER.log(Level.FINE, "logged out: {0}", username);
        for (SecurityListener l : all()) {
            l.loggedOut(username);
        }
    }

    private static List<SecurityListener> all() {
        return Jenkins.getInstance().getExtensionList(SecurityListener.class);
    }
}