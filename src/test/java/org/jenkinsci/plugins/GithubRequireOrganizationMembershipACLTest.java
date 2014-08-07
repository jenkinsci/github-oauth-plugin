/**
 The MIT License

Copyright (c) 2014 Alex Rothenberg

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

import hudson.model.Hudson;
import hudson.model.Item;
import hudson.model.Project;
import hudson.plugins.git.GitSCM;
import hudson.plugins.git.UserRemoteConfig;
import hudson.scm.NullSCM;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import junit.framework.TestCase;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 *
 * @author alex
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest( GitHub.class )
public class GithubRequireOrganizationMembershipACLTest extends TestCase {

    private GithubRequireOrganizationMembershipACL aclForProject(Project project) {
        boolean useRepositoryPermissions = true;
        boolean authenticatedUserReadPermission = true;
        boolean authenticatedUserCreateJobPermission = false;

        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                authenticatedUserReadPermission, useRepositoryPermissions, authenticatedUserCreateJobPermission,
                false, true, true, true);
        return acl.cloneForProject(project);
    }

    private GitHub mockGithubAs(String username) throws IOException {
        GitHub gh = PowerMockito.mock(GitHub.class);
        PowerMockito.mockStatic(GitHub.class);
        PowerMockito.when(GitHub.connectUsingOAuth("https://api.github.com", "accessToken")).thenReturn(gh);
        GHUser me = PowerMockito.mock(GHMyself.class);
        PowerMockito.when(gh.getMyself()).thenReturn((GHMyself) me);
        PowerMockito.when(me.getLogin()).thenReturn(username);
        return gh;
    }

    private Project mockProject(String url) {
        Project project = PowerMockito.mock(Project.class);
        GitSCM gitSCM = PowerMockito.mock(GitSCM.class);
        UserRemoteConfig userRemoteConfig = PowerMockito.mock(UserRemoteConfig.class);
        List<UserRemoteConfig> userRemoteConfigs = Arrays.asList(userRemoteConfig);
        PowerMockito.when(project.getScm()).thenReturn(gitSCM);
        PowerMockito.when(gitSCM.getUserRemoteConfigs()).thenReturn(userRemoteConfigs);
        PowerMockito.when(userRemoteConfig.getUrl()).thenReturn(url);
        return project;
    }

    private void mockGithubRepositoryWithCollaborators(GitHub mockGithub, String name, boolean isPrivate, List<String> collaboratorNames) throws IOException {
        GHRepository ghRepository = PowerMockito.mock(GHRepository.class);
        PowerMockito.when(mockGithub.getRepository(name)).thenReturn(ghRepository);
        PowerMockito.when(ghRepository.isPrivate()).thenReturn(isPrivate);
        Set<String> names = new HashSet(collaboratorNames);
        PowerMockito.when(ghRepository.getCollaboratorNames()).thenReturn(names);
    }

    @Test
    public void testCanReadPublicRepository() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
        mockGithubRepositoryWithCollaborators(mockGithub, "some-org/a-public-repo", false, Arrays.asList("someone"));

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testCanBuildPrivateRepositoryICollaborateOn() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = mockProject("https://github.com/some-org/a-private-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
        mockGithubRepositoryWithCollaborators(mockGithub, "some-org/a-private-repo", true, Arrays.asList("Him", "Me", "Her", "You"));

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.BUILD));
    }

    @Test
    public void testCanNotBuildPrivateRepositoryIDoNotCollaborateOn() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = mockProject("https://github.com/some-org/another-private-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
        mockGithubRepositoryWithCollaborators(mockGithub, "some-org/another-private-repo", true, Arrays.asList("Him", "Her", "You"));

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.BUILD));
    }

    @Test
    public void testCanNotBuildPublicRepositoryIDoNotCollaborateOn() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
        mockGithubRepositoryWithCollaborators(mockGithub, "some-org/a-public-repo", false, Arrays.asList("someone"));

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.BUILD));
    }

    @Test
    public void testCanReadPrivateRepositoryICollaborateOn() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = mockProject("https://github.com/some-org/a-private-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
        mockGithubRepositoryWithCollaborators(mockGithub, "some-org/a-private-repo", true, Arrays.asList("Him", "Me", "Her", "You"));

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testCanNotReadPrivateRepositoryIDoNotCollaborateOn() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = mockProject("https://github.com/some-org/another-private-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
        mockGithubRepositoryWithCollaborators(mockGithub, "some-org/another-private-repo", true, Arrays.asList("Him", "Her", "You"));

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testNotGrantedBuildWhenNotUsingGitSCM() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = PowerMockito.mock(Project.class);
        PowerMockito.when(mockProject.getScm()).thenReturn(new NullSCM());

        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testNotGrantedBuildWhenRepositoryIsEmpty() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = mockProject(null);
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testNotGrantedReadWhenRepositoryUrlIsEmpty() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = PowerMockito.mock(Project.class);
        PowerMockito.when(mockProject.getScm()).thenReturn(new NullSCM());
        GitSCM gitSCM = PowerMockito.mock(GitSCM.class);
        List<UserRemoteConfig> userRemoteConfigs = Collections.<UserRemoteConfig>emptyList();
        PowerMockito.when(mockProject.getScm()).thenReturn(gitSCM);
        PowerMockito.when(gitSCM.getUserRemoteConfigs()).thenReturn(userRemoteConfigs);

        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testGlobalReadAvailableDueToAuthenticatedUserReadPermission() throws IOException {
        GitHub mockGithub = mockGithubAs("Me");
        Project mockProject = mockProject("https://github.com/some-org/another-private-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Hudson.READ));

    }

    @Test
    public void testWithoutUseRepositoryPermissionsSetCanReadDueToAuthenticatedUserReadPermission() throws IOException {
        boolean useRepositoryPermissions = false;
        boolean authenticatedUserReadPermission = true;
        mockGithubAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                authenticatedUserReadPermission, useRepositoryPermissions, true, false, true, true, true);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testWithoutUseRepositoryPermissionsSetCannotReadWithoutToAuthenticatedUserReadPermission() throws IOException {
        boolean useRepositoryPermissions = false;
        boolean authenticatedUserReadPermission = false;
        mockGithubAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                authenticatedUserReadPermission, useRepositoryPermissions, true, false, true, true, true);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testUsersCannotCreateWithoutConfigurationEnabledPermission() throws IOException {
        boolean authenticatedUserCreateJobPermission = false;
        mockGithubAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, false, true, true, true);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.CREATE));
    }

    @Test
    public void testUsersCanCreateWithConfigurationEnabledPermission() throws IOException {
        boolean authenticatedUserCreateJobPermission = true;
        mockGithubAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, false, true, true, true);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.CREATE));
    }

    @Test
    public void testCanReadConfigureDeleteAProjectWithAuthenticatedUserReadPermission() throws IOException {
        String nullProjectName = null;
        Project mockProject = mockProject(nullProjectName);
        boolean authenticatedUserCreateJobPermission = true;
        mockGithubAs("Me");
        GithubRequireOrganizationMembershipACL globalAcl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, false, true, true, true);
        GithubRequireOrganizationMembershipACL acl = globalAcl.cloneForProject(mockProject);
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.READ));
        assertTrue(acl.hasPermission(authenticationToken, Item.CONFIGURE));
        assertTrue(acl.hasPermission(authenticationToken, Item.DELETE));
        assertTrue(acl.hasPermission(authenticationToken, Item.EXTENDED_READ));
    }

    @Test
    public void testCannotReadConfigureDeleteAProjectWithoutToAuthenticatedUserReadPermission() throws IOException {
        String nullProjectName = null;
        Project mockProject = mockProject(nullProjectName);
        boolean authenticatedUserCreateJobPermission = false;
        mockGithubAs("Me");
        GithubRequireOrganizationMembershipACL globalAcl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, false, true, true, true);
        GithubRequireOrganizationMembershipACL acl = globalAcl.cloneForProject(mockProject);
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        assertFalse(acl.hasPermission(authenticationToken, Item.CONFIGURE));
        assertFalse(acl.hasPermission(authenticationToken, Item.DELETE));
        assertFalse(acl.hasPermission(authenticationToken, Item.EXTENDED_READ));
    }

    private GithubRequireOrganizationMembershipACL aclWithConfigureForProject(Project project) {
        boolean useRepositoryPermissions = true;
        boolean authenticatedUserReadPermission = true;
        boolean repositoryUserConfigurePermission = true;
        boolean authenticatedUserCreateJobPermission = true;

        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                authenticatedUserReadPermission, useRepositoryPermissions, authenticatedUserCreateJobPermission,
                authenticatedUserCreateJobPermission, true, true, true);
        return acl.cloneForProject(project);
    }

    @Test
    public void testCannotReadDeleteAProjectWithoutToAuthenticatedUserReadPermissionWithRepositoryReadPermission() throws IOException {
        String nullProjectName = null;
        Project mockProject = mockProject(nullProjectName);
        boolean authenticatedUserCreateJobPermission = false;
        mockGithubAs("Me");
        GithubRequireOrganizationMembershipACL globalAcl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, true, true, true, true);
        GithubRequireOrganizationMembershipACL acl = globalAcl.cloneForProject(mockProject);
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        assertTrue(acl.hasPermission(authenticationToken, Item.CONFIGURE));
        assertFalse(acl.hasPermission(authenticationToken, Item.DELETE));
        assertFalse(acl.hasPermission(authenticationToken, Item.EXTENDED_READ));
    }

        @Test
    public void testCannotReadConfigureDeleteAProjectWithoutToAuthenticatedUserReadPermissionWithoutRepositoryReadPermission() throws IOException {
        String nullProjectName = null;
        Project mockProject = mockProject(nullProjectName);
        boolean authenticatedUserCreateJobPermission = false;
        mockGithubAs("Me");
        GithubRequireOrganizationMembershipACL globalAcl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, true, true, true, true);
        GithubRequireOrganizationMembershipACL acl = globalAcl.cloneForProject(mockProject);
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        assertFalse(acl.hasPermission(authenticationToken, Item.CONFIGURE));
        assertFalse(acl.hasPermission(authenticationToken, Item.DELETE));
        assertFalse(acl.hasPermission(authenticationToken, Item.EXTENDED_READ));
    }
}
