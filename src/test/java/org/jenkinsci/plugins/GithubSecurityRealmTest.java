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

import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class GithubSecurityRealmTest {

    @Test
    void testEquals_true(JenkinsRule rule) {
        GithubSecurityRealm a = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org");
        GithubSecurityRealm b = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org");
        assertEquals(a, b);
    }

    @Test
    void testEquals_false(JenkinsRule rule) {
        GithubSecurityRealm a = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org");
        GithubSecurityRealm b = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org,repo");
        assertNotEquals(a, b);
        assertNotEquals("", a);
    }

    @Test
    void testHasScope_true(JenkinsRule rule) {
        GithubSecurityRealm a = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org,user,user:email");
        assertTrue(a.hasScope("user"));
        assertTrue(a.hasScope("read:org"));
        assertTrue(a.hasScope("user:email"));
    }

    @Test
    void testHasScope_false(JenkinsRule rule) {
        GithubSecurityRealm a = new GithubSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "read:org,user,user:email");
        assertFalse(a.hasScope("somescope"));
    }

    @Test
    void testDescriptorImplGetDefaultGithubWebUri(JenkinsRule rule) {
        GithubSecurityRealm.DescriptorImpl descriptor = new GithubSecurityRealm.DescriptorImpl();
        assertEquals("https://github.com", descriptor.getDefaultGithubWebUri());
    }

    @Test
    void testDescriptorImplGetDefaultGithubApiUri(JenkinsRule rule) {
        GithubSecurityRealm.DescriptorImpl descriptor = new GithubSecurityRealm.DescriptorImpl();
        assertEquals("https://api.github.com", descriptor.getDefaultGithubApiUri());
    }

    @Test
    void testDescriptorImplGetDefaultOauthScopes(JenkinsRule rule) {
        GithubSecurityRealm.DescriptorImpl descriptor = new GithubSecurityRealm.DescriptorImpl();
        assertEquals("read:org,user:email,repo", descriptor.getDefaultOauthScopes());
    }
}
