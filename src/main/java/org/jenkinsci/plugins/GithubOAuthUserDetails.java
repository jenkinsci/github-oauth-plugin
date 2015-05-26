/**
 *
 */
package org.jenkinsci.plugins;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.github.GHUser;

/**
 * @author Mike
 *
 */
public class GithubOAuthUserDetails extends User implements UserDetails {

    private static final long serialVersionUID = 1L;

    public GithubOAuthUserDetails(GHUser user, GrantedAuthority[] authorities) {
        super(user.getLogin(), "", true, true, true, true, authorities);
    }

}
