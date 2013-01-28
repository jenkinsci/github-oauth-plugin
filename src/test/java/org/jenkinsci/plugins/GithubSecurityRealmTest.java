package org.jenkinsci.plugins;

import junit.framework.TestCase;

/**
 * @author Johno Crawford (johno@hellface.com)
 */
public class GithubSecurityRealmTest extends TestCase {

    private GithubSecurityRealm realm;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        realm = new GithubSecurityRealm(null, null, null);
    }

    public void testGitHubServerUrl() throws Exception {
        String authenticationUrl = realm.extractAuthenticationUrl("https://github.com");
        assertEquals("https://github.com", authenticationUrl);
    }

    public void testEnterpriseServerUrl() throws Exception {
        String authenticationUrl = realm.extractAuthenticationUrl("http://ghe.acme.com/api/v3/");
        assertEquals("http://ghe.acme.com", authenticationUrl);
    }
}
