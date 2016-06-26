/**
 The MIT License

Copyright (c) 2016 Sam Gleske

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

import jenkins.model.Jenkins;
import junit.framework.TestCase;
import org.jenkinsci.plugins.GithubSecurityRealm.DescriptorImpl;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Jenkins.class, GithubSecurityRealm.class, DescriptorImpl.class})
public class GithubLogoutActionTest extends TestCase {

    @Mock
    private Jenkins jenkins;

    @Mock
    private GithubSecurityRealm securityRealm;

    @Mock
    private DescriptorImpl descriptor;

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(Jenkins.class);
        PowerMockito.when(Jenkins.getInstance()).thenReturn(jenkins);
        PowerMockito.when(jenkins.getSecurityRealm()).thenReturn(securityRealm);
        PowerMockito.when(securityRealm.getDescriptor()).thenReturn(descriptor);
        PowerMockito.when(descriptor.getDefaultGithubWebUri()).thenReturn("https://github.com");
    }

    private void mockGithubSecurityRealmWebUriFor(String host) {
        PowerMockito.when(securityRealm.getGithubWebUri()).thenReturn(host);
    }

    @Test
    public void testGetGitHubText_gh() {
        mockGithubSecurityRealmWebUriFor("https://github.com");
        GithubLogoutAction ghlogout = new GithubLogoutAction();
        assertEquals("GitHub", ghlogout.getGitHubText());
    }

    @Test
    public void testGetGitHubText_ghe() {
        mockGithubSecurityRealmWebUriFor("https://ghe.example.com");
        GithubLogoutAction ghlogout = new GithubLogoutAction();
        assertEquals("GitHub Enterprise", ghlogout.getGitHubText());
    }
}
