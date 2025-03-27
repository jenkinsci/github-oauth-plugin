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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class GithubLogoutActionTest {

    @Mock
    private GithubSecurityRealm securityRealm;

    @Mock
    private GithubSecurityRealm.DescriptorImpl descriptor;

    private void mockJenkins(MockedStatic<Jenkins> mockedJenkins) {
        Jenkins jenkins = Mockito.mock(Jenkins.class);
        mockedJenkins.when(Jenkins::get).thenReturn(jenkins);
        Mockito.when(jenkins.getSecurityRealm()).thenReturn(securityRealm);
        Mockito.when(securityRealm.getDescriptor()).thenReturn(descriptor);
        Mockito.when(descriptor.getDefaultGithubWebUri()).thenReturn("https://github.com");
    }

    private void mockGithubSecurityRealmWebUriFor(String host) {
        Mockito.when(securityRealm.getGithubWebUri()).thenReturn(host);
    }

    @Test
    void testGetGitHubText_gh() {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class)) {
            mockJenkins(mockedJenkins);
            mockGithubSecurityRealmWebUriFor("https://github.com");
            GithubLogoutAction ghlogout = new GithubLogoutAction();
            assertEquals("GitHub", ghlogout.getGitHubText());
        }
    }

    @Test
    void testGetGitHubText_ghe() {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class)) {
            mockJenkins(mockedJenkins);
            mockGithubSecurityRealmWebUriFor("https://ghe.example.com");
            GithubLogoutAction ghlogout = new GithubLogoutAction();
            assertEquals("GitHub Enterprise", ghlogout.getGitHubText());
        }
    }
}
