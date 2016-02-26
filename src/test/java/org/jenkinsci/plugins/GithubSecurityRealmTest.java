/**
 The MIT License

Copyright (c) 2015 Sam Gleske

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

package org.jenkinsci.plugins;

import hudson.util.Secret;
import java.io.IOException;
import junit.framework.TestCase;
import org.jenkinsci.plugins.GithubSecurityRealm.DescriptorImpl;
import org.junit.runner.RunWith;
import org.junit.Test;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.api.mockito.PowerMockito;
import org.junit.Before;
import org.mockito.Mockito;
import java.security.GeneralSecurityException;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Secret.class})
public class GithubSecurityRealmTest extends TestCase {

    @Before
    public void setUp() throws Exception {
        //skip attempting to decrypt a secret
        PowerMockito.mockStatic(Secret.class);
        PowerMockito.when(Secret.class ,"decrypt", Mockito.any(String.class)).thenReturn((Secret) null);
    }

    @Test
    public void testEquals_true() {
        GithubSecurityRealm a = new GithubSecurityRealm(new String("http://jenkins.acme.com"), new String("http://jenkins.acme.com/api/v3"), new String("someid"), new String("somesecret"), new String("read:org"));
        GithubSecurityRealm b = new GithubSecurityRealm(new String("http://jenkins.acme.com"), new String("http://jenkins.acme.com/api/v3"), new String("someid"), new String("somesecret"), new String("read:org"));
        assertTrue(a.equals(b));
    }

    @Test
    public void testEquals_false() {
        GithubSecurityRealm a = new GithubSecurityRealm(new String("http://jenkins.acme.com"), new String("http://jenkins.acme.com/api/v3"), new String("someid"), new String("somesecret"), new String("read:org"));
        GithubSecurityRealm b = new GithubSecurityRealm(new String("http://jenkins.acme.com"), new String("http://jenkins.acme.com/api/v3"), new String("someid"), new String("somesecret"), new String("read:org,repo"));
        assertFalse(a.equals(b));
        assertFalse(a.equals(""));
    }

    @Test
    public void testHasScope_true() {
        GithubSecurityRealm a = new GithubSecurityRealm(new String("http://jenkins.acme.com"), new String("http://jenkins.acme.com/api/v3"), new String("someid"), new String("somesecret"), new String("read:org,user,user:email"));
        assertTrue(a.hasScope(new String("user")));
        assertTrue(a.hasScope(new String("read:org")));
        assertTrue(a.hasScope(new String("user:email")));
    }

    @Test
    public void testHasScope_false() {
        GithubSecurityRealm a = new GithubSecurityRealm(new String("http://jenkins.acme.com"), new String("http://jenkins.acme.com/api/v3"), new String("someid"), new String("somesecret"), new String("read:org,user,user:email"));
        assertFalse(a.hasScope(new String("somescope")));
    }

    @Test
    public void testDescriptorImplGetDefaultGithubWebUri() {
        DescriptorImpl descriptor = new DescriptorImpl();
        assertTrue("https://github.com".equals(descriptor.getDefaultGithubWebUri()));
    }

    @Test
    public void testDescriptorImplGetDefaultGithubApiUri() {
        DescriptorImpl descriptor = new DescriptorImpl();
        assertTrue("https://api.github.com".equals(descriptor.getDefaultGithubApiUri()));
    }

    @Test
    public void testDescriptorImplGetDefaultOauthScopes() {
        DescriptorImpl descriptor = new DescriptorImpl();
        assertTrue("read:org,user:email".equals(descriptor.getDefaultOauthScopes()));
    }
}
