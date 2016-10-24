/**
 *
 */
package org.jenkinsci.plugins;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.github.GHUser;

import javax.annotation.Nonnull;
import java.io.IOException;

/**
 * @author Mike
 *
 */
@SuppressFBWarnings("EQ_DOESNT_OVERRIDE_EQUALS")
public class GithubOAuthUserDetails extends User implements UserDetails {

    private static final long serialVersionUID = 1L;

    private final GithubAuthenticationToken authenticationToken;

    public GithubOAuthUserDetails(@Nonnull String login, @Nonnull GrantedAuthority[] authorities) {
        super(login, "", true, true, true, true, authorities);
        this.authenticationToken = null;
    }

    public GithubOAuthUserDetails(@Nonnull String login, @Nonnull GithubAuthenticationToken authenticationToken) {
        super(login, "", true, true, true, true, null);
        this.authenticationToken = authenticationToken;
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        if (super.getAuthorities() == null) {
            try {
                GHUser user = authenticationToken.loadUser(getUsername());
                setAuthorities(authenticationToken.getGrantedAuthorities(user));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return super.getAuthorities();
    }
}
