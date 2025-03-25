/**
 *
 */
package org.jenkinsci.plugins;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author Mike
 *
 */
public class GithubOAuthUserDetails extends User implements UserDetails {

    private static final long serialVersionUID = 1L;

    public GithubOAuthUserDetails(@NonNull String login, @NonNull Collection<? extends GrantedAuthority> authorities) {
        super(login, "", true, true, true, true, authorities);
    }

}
