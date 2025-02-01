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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class GithubSecurityRealmTest {

    @ClassRule
    public final static JenkinsRule rule = new JenkinsRule();

    @Test
    public void testEquals_true() {
        GithubSecurityRealm a = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org");
        GithubSecurityRealm b = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org");
        assertEquals(a, b);
    }

    @Test
    public void testEquals_false() {
        GithubSecurityRealm a = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org");
        GithubSecurityRealm b = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org,repo");
        assertNotEquals(a, b);
        assertNotEquals("", a);
    }

    @Test
    public void testHasScope_true() {
        GithubSecurityRealm a = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org,user,user:email");
        assertTrue(a.hasScope("user"));
        assertTrue(a.hasScope("read:org"));
        assertTrue(a.hasScope("user:email"));
    }

    @Test
    public void testHasScope_false() {
        GithubSecurityRealm a = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org,user,user:email");
        assertFalse(a.hasScope("somescope"));
    }

    @Test
    public void testDescriptorImplGetDefaultGithubWebUri() {
        GithubSecurityRealm.DescriptorImpl descriptor = new GithubSecurityRealm.DescriptorImpl();
        assertEquals("https://github.com", descriptor.getDefaultGithubWebUri());
    }

    @Test
    public void testDescriptorImplGetDefaultGithubApiUri() {
        GithubSecurityRealm.DescriptorImpl descriptor = new GithubSecurityRealm.DescriptorImpl();
        assertEquals("https://api.github.com", descriptor.getDefaultGithubApiUri());
    }

    @Test
    public void testDescriptorImplGetDefaultOauthScopes() {
        GithubSecurityRealm.DescriptorImpl descriptor = new GithubSecurityRealm.DescriptorImpl();
        assertEquals("read:org,user:email,repo", descriptor.getDefaultOauthScopes());
    }
}
