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

    private boolean hasGrantedAuthorities;

    private final GithubAuthenticationToken authenticationToken;

    public GithubOAuthUserDetails(@Nonnull String login, @Nonnull GrantedAuthority[] authorities) {
        super(login, "", true, true, true, true, authorities);
        this.authenticationToken = null;
        this.hasGrantedAuthorities = true;
    }

    public GithubOAuthUserDetails(@Nonnull String login, @Nonnull GithubAuthenticationToken authenticationToken) {
        super(login, "", true, true, true, true, new GrantedAuthority[0]);
        this.authenticationToken = authenticationToken;
        this.hasGrantedAuthorities = false;
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        if (!hasGrantedAuthorities) {
            try {
                GHUser user = authenticationToken.loadUser(getUsername());
                if(user != null) {
                    setAuthorities(authenticationToken.getGrantedAuthorities(user));
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return super.getAuthorities();
    }
}
