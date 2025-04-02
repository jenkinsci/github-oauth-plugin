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

import hudson.model.Computer;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.model.Messages;
import hudson.model.Project;
import hudson.plugins.git.GitSCM;
import hudson.plugins.git.UserRemoteConfig;
import hudson.scm.NullSCM;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import jenkins.branch.Branch;
import jenkins.branch.MultiBranchProject;
import jenkins.model.Jenkins;
import jenkins.scm.api.SCMSource;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.multibranch.BranchJobProperty;
import org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHPerson;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.PagedIterable;
import org.kohsuke.github.RateLimitHandler;
import org.kohsuke.github.extras.okhttp3.OkHttpGitHubConnector;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author alex
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GithubRequireOrganizationMembershipACLTest {

    private GitHub gh;

    @Mock
    private GithubSecurityRealm securityRealm;

    private boolean allowAnonymousReadPermission;
    private boolean allowAnonymousJobStatusPermission;
    private boolean useRepositoryPermissions;
    private boolean authenticatedUserReadPermission;
    private boolean authenticatedUserCreateJobPermission;
    private boolean allowAnonymousWebhookPermission;
    private boolean allowAnonymousCCTrayPermission;

    @BeforeEach
    void setUp() {
        // default to: use repository permissions; don't allow anonymous read/view status; don't allow authenticated read/create
        allowAnonymousReadPermission = false;
        allowAnonymousJobStatusPermission = false;
        useRepositoryPermissions = true;
        authenticatedUserReadPermission = false;
        authenticatedUserCreateJobPermission = false;
        allowAnonymousWebhookPermission = false;
        allowAnonymousCCTrayPermission = false;

        Mockito.when(securityRealm.getOauthScopes()).thenReturn("read:org,repo");
        Mockito.when(securityRealm.hasScope("read:org")).thenReturn(true);
        Mockito.when(securityRealm.hasScope("repo")).thenReturn(true);
    }

    private void mockJenkins(MockedStatic<Jenkins> mockedJenkins) {
        Jenkins jenkins = Mockito.mock(Jenkins.class);
        mockedJenkins.when(Jenkins::get).thenReturn(jenkins);
        Mockito.when(jenkins.getSecurityRealm()).thenReturn(securityRealm);
        Mockito.when(jenkins.getRootUrl()).thenReturn("https://www.jenkins.org/");
    }

    private static final Permission VIEW_JOBSTATUS_PERMISSION = new Permission(Item.PERMISSIONS,
            "ViewStatus",
            Messages._Item_READ_description(),
            Permission.READ,
            PermissionScope.ITEM);
    private static final Authentication ANONYMOUS_USER = new AnonymousAuthenticationToken("anonymous",
            "anonymous",
            List.of(new SimpleGrantedAuthority("anonymous")));

    private GithubRequireOrganizationMembershipACL createACL() {
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL(
                "admin",
                "myOrg",
                authenticatedUserReadPermission,
                useRepositoryPermissions,
                authenticatedUserCreateJobPermission,
                allowAnonymousWebhookPermission,
                allowAnonymousCCTrayPermission,
                allowAnonymousReadPermission,
                allowAnonymousJobStatusPermission);
        acl.setAgentUserName("agent");
        return acl;
    }

    private GithubRequireOrganizationMembershipACL aclForProject(Project project) {
        return createACL().cloneForProject(project);
    }

    private GithubRequireOrganizationMembershipACL aclForMultiBranchProject(MultiBranchProject multiBranchProject) {
        return createACL().cloneForProject(multiBranchProject);
    }

    private GithubRequireOrganizationMembershipACL aclForWorkflowJob(WorkflowJob workflowJob) {
        return createACL().cloneForProject(workflowJob);
    }

    private GHMyself mockGHMyselfAs(MockedStatic<GitHubBuilder> mockedGitHubBuilder, String username) throws IOException {
        gh = Mockito.mock(GitHub.class);
        GitHubBuilder builder = Mockito.mock(GitHubBuilder.class);
        mockedGitHubBuilder.when(GitHubBuilder::fromEnvironment).thenReturn(builder);
        Mockito.when(builder.withEndpoint("https://api.github.com")).thenReturn(builder);
        Mockito.when(builder.withOAuthToken("accessToken")).thenReturn(builder);
        Mockito.when(builder.withRateLimitHandler(RateLimitHandler.FAIL)).thenReturn(builder);
        Mockito.when(builder.withConnector(Mockito.any(OkHttpGitHubConnector.class))).thenReturn(builder);
        Mockito.when(builder.build()).thenReturn(gh);
        GHMyself me = Mockito.mock(GHMyself.class);
        Mockito.when(gh.getMyself()).thenReturn(me);
        Mockito.when(me.getLogin()).thenReturn(username);
        mockReposFor(me, Collections.emptyList());
        return me;
    }

    // TODO: Add ability to set list of orgs user belongs to to check whitelisting!

    private static void mockReposFor(GHPerson person, List<GHRepository> repositories) {
        PagedIterable<GHRepository> pagedRepositories = Mockito.mock(PagedIterable.class);
        Mockito.when(person.listRepositories(100)).thenReturn(pagedRepositories);
        Mockito.when(pagedRepositories.asList()).thenReturn(repositories);
    }

    private GHRepository mockRepository(String repositoryName, boolean isPublic, boolean admin, boolean push, boolean pull) throws IOException {
        GHRepository ghRepository = Mockito.mock(GHRepository.class);
        Mockito.when(gh.getRepository(repositoryName)).thenReturn(ghRepository);
        Mockito.when(ghRepository.isPrivate()).thenReturn(!isPublic);
        Mockito.when(ghRepository.hasAdminAccess()).thenReturn(admin);
        Mockito.when(ghRepository.hasPushAccess()).thenReturn(push);
        Mockito.when(ghRepository.hasPullAccess()).thenReturn(pull);
        Mockito.when(ghRepository.getFullName()).thenReturn(repositoryName);
        return ghRepository;
    }

    private GHRepository mockPublicRepository(String repositoryName) throws IOException {
        return mockRepository(repositoryName, true, false, false, false);
    }

    private static Project mockProject(String url) {
        Project project = Mockito.mock(Project.class);
        GitSCM gitSCM = Mockito.mock(GitSCM.class);
        UserRemoteConfig userRemoteConfig = Mockito.mock(UserRemoteConfig.class);
        List<UserRemoteConfig> userRemoteConfigs = Collections.singletonList(userRemoteConfig);
        Mockito.when(project.getScm()).thenReturn(gitSCM);
        Mockito.when(gitSCM.getUserRemoteConfigs()).thenReturn(userRemoteConfigs);
        Mockito.when(userRemoteConfig.getUrl()).thenReturn(url);
        return project;
    }

    private static WorkflowJob mockWorkflowJob(String url) {
        WorkflowJob project = Mockito.mock(WorkflowJob.class);
        GitSCM gitSCM = Mockito.mock(GitSCM.class);
        Branch branch = Mockito.mock(Branch.class);
        BranchJobProperty branchJobProperty = Mockito.mock(BranchJobProperty.class);
        UserRemoteConfig userRemoteConfig = Mockito.mock(UserRemoteConfig.class);
        List<UserRemoteConfig> userRemoteConfigs = Collections.singletonList(userRemoteConfig);
        Mockito.when(project.getProperty(BranchJobProperty.class)).thenReturn(branchJobProperty);
        Mockito.when(branchJobProperty.getBranch()).thenReturn(branch);
        Mockito.when(branch.getScm()).thenReturn(gitSCM);
        Mockito.when(gitSCM.getUserRemoteConfigs()).thenReturn(userRemoteConfigs);
        Mockito.when(userRemoteConfig.getUrl()).thenReturn(url);
        return project;
    }

    private static MultiBranchProject mockMultiBranchProject(String url) {
        WorkflowMultiBranchProject multiBranchProject = Mockito.mock(WorkflowMultiBranchProject.class);
        GitHubSCMSource gitHubSCM = Mockito.mock(GitHubSCMSource.class);
        ArrayList<SCMSource> scmSources = new ArrayList<>();
        scmSources.add(gitHubSCM);
        Mockito.when(multiBranchProject.getSCMSources()).thenReturn(scmSources);
        Mockito.when(gitHubSCM.getRemote()).thenReturn(url);
        return multiBranchProject;
    }

    @AfterEach
    void tearDown() {
        gh = null;
        GithubAuthenticationToken.clearCaches();
    }

    @Test
    void testCanReadAndBuildOneOfMyPrivateRepositories() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            GHMyself me = mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GHRepository repo = mockRepository("me/a-repo", false, true, true, true); // private; admin, push, and pull rights
            mockReposFor(me, Collections.singletonList(repo)); // hook to my listing
            String repoUrl = "https://github.com/me/a-repo.git";
            Project mockProject = mockProject(repoUrl);
            MultiBranchProject mockMultiBranchProject = mockMultiBranchProject(repoUrl);
            WorkflowJob mockWorkflowJob = mockWorkflowJob(repoUrl);
            GithubRequireOrganizationMembershipACL workflowJobAcl = aclForWorkflowJob(mockWorkflowJob);
            GithubRequireOrganizationMembershipACL multiBranchProjectAcl = aclForMultiBranchProject(mockMultiBranchProject);
            GithubRequireOrganizationMembershipACL projectAcl = aclForProject(mockProject);
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.BUILD));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.BUILD));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.BUILD));
        }
    }

    @Test
    void testCanReadAndBuildAPublicRepository() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            GHMyself me = mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GHRepository repo = mockPublicRepository("node/node");
            String repoUrl = "https://github.com/node/node.git";
            Project mockProject = mockProject(repoUrl);
            MultiBranchProject mockMultiBranchProject = mockMultiBranchProject(repoUrl);
            WorkflowJob mockWorkflowJob = mockWorkflowJob(repoUrl);
            GithubRequireOrganizationMembershipACL workflowJobAcl = aclForWorkflowJob(mockWorkflowJob);
            GithubRequireOrganizationMembershipACL multiBranchProjectAcl = aclForMultiBranchProject(mockMultiBranchProject);
            GithubRequireOrganizationMembershipACL projectAcl = aclForProject(mockProject);
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.BUILD));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.BUILD));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.BUILD));
        }
    }

    @Test
    void testCanReadAndBuildPrivateRepositoryIHavePullRightsOn() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            GHMyself me = mockGHMyselfAs(mockedGitHubBuilder, "Me");
            // private repo I have pull rights to
            GHRepository repo = mockRepository("some-org/a-private-repo", false, false, false, true);
            mockReposFor(me, Collections.singletonList(repo));
            String repoUrl = "https://github.com/some-org/a-private-repo.git";
            Project mockProject = mockProject(repoUrl);
            MultiBranchProject mockMultiBranchProject = mockMultiBranchProject(repoUrl);
            WorkflowJob mockWorkflowJob = mockWorkflowJob(repoUrl);
            GithubRequireOrganizationMembershipACL workflowJobAcl = aclForWorkflowJob(mockWorkflowJob);
            GithubRequireOrganizationMembershipACL multiBranchProjectAcl = aclForMultiBranchProject(mockMultiBranchProject);
            GithubRequireOrganizationMembershipACL projectAcl = aclForProject(mockProject);

            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(projectAcl.hasPermission2(authenticationToken, Item.BUILD));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(workflowJobAcl.hasPermission2(authenticationToken, Item.BUILD));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertTrue(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.BUILD));
        }
    }

    @Test
    void testCanNotReadOrBuildRepositoryIDoNotCollaborateOn() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            GHMyself me = mockGHMyselfAs(mockedGitHubBuilder, "Me");

            String repoUrl = "https://github.com/some-org/another-private-repo.git";
            Project mockProject = mockProject(repoUrl);
            MultiBranchProject mockMultiBranchProject = mockMultiBranchProject(repoUrl);
            WorkflowJob mockWorkflowJob = mockWorkflowJob(repoUrl);
            GithubRequireOrganizationMembershipACL workflowJobAcl = aclForWorkflowJob(mockWorkflowJob);
            GithubRequireOrganizationMembershipACL multiBranchProjectAcl = aclForMultiBranchProject(mockMultiBranchProject);
            GithubRequireOrganizationMembershipACL projectAcl = aclForProject(mockProject);

            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(projectAcl.hasPermission2(authenticationToken, Item.READ));
            assertFalse(projectAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertFalse(projectAcl.hasPermission2(authenticationToken, Item.BUILD));
            assertFalse(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.READ));
            assertFalse(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertFalse(multiBranchProjectAcl.hasPermission2(authenticationToken, Item.BUILD));
            assertFalse(workflowJobAcl.hasPermission2(authenticationToken, Item.READ));
            assertFalse(workflowJobAcl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertFalse(workflowJobAcl.hasPermission2(authenticationToken, Item.BUILD));
        }
    }

    @Test
    void testNotGrantedBuildWhenNotUsingGitSCM() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            Project mockProject = Mockito.mock(Project.class);
            Mockito.when(mockProject.getScm()).thenReturn(new NullSCM());

            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission2(authenticationToken, Item.READ));
            assertFalse(acl.hasPermission2(authenticationToken, Item.DISCOVER));
        }
    }

    @Test
    void testNotGrantedBuildWhenRepositoryIsEmpty() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            Project mockProject = mockProject(null);
            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission2(authenticationToken, Item.READ));
            assertFalse(acl.hasPermission2(authenticationToken, Item.DISCOVER));
        }
    }

    @Test
    void testNotGrantedReadWhenRepositoryUrlIsEmpty() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            Project mockProject = Mockito.mock(Project.class);
            Mockito.when(mockProject.getScm()).thenReturn(new NullSCM());
            GitSCM gitSCM = Mockito.mock(GitSCM.class);
            List<UserRemoteConfig> userRemoteConfigs = Collections.emptyList();
            Mockito.when(mockProject.getScm()).thenReturn(gitSCM);
            Mockito.when(gitSCM.getUserRemoteConfigs()).thenReturn(userRemoteConfigs);

            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission2(authenticationToken, Item.READ));
            assertFalse(acl.hasPermission2(authenticationToken, Item.DISCOVER));
        }
    }

    @Test
    void testGlobalReadAvailableDueToAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.useRepositoryPermissions = false;
            this.authenticatedUserReadPermission = true;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(acl.hasPermission2(authenticationToken, Hudson.READ));
        }
    }

    @Test
    void testWithoutUseRepositoryPermissionsSetCanReadDueToAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.useRepositoryPermissions = false;
            this.authenticatedUserReadPermission = true;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(acl.hasPermission2(authenticationToken, Item.READ));
        }
    }

    @Test
    void testWithoutUseRepositoryPermissionsSetCannotReadWithoutAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.useRepositoryPermissions = false;
            this.authenticatedUserReadPermission = false;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission2(authenticationToken, Item.READ));
        }
    }

    @Test
    void testUsersCannotCreateWithoutConfigurationEnabledPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.authenticatedUserCreateJobPermission = false;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission2(authenticationToken, Item.CREATE));
        }
    }

    @Test
    void testUsersCanCreateWithConfigurationEnabledPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.authenticatedUserCreateJobPermission = true;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(acl.hasPermission2(authenticationToken, Item.CREATE));
        }
    }

    @Test
    void testCanReadAProjectWithAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.authenticatedUserReadPermission = true;

            String nullProjectName = null;
            Project mockProject = mockProject(nullProjectName);
            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            // Gives the user rights to see the project
            assertTrue(acl.hasPermission2(authenticationToken, Item.READ));
            assertTrue(acl.hasPermission2(authenticationToken, Item.DISCOVER));
            // but not to build, cancel, configure, view configuration, delete it
            assertFalse(acl.hasPermission2(authenticationToken, Item.BUILD));
            assertFalse(acl.hasPermission2(authenticationToken, Item.CONFIGURE));
            assertFalse(acl.hasPermission2(authenticationToken, Item.DELETE));
            assertFalse(acl.hasPermission2(authenticationToken, Item.EXTENDED_READ));
            assertFalse(acl.hasPermission2(authenticationToken, Item.CANCEL));
        }
    }

    @Test
    void testCannotReadAProjectWithoutAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.authenticatedUserReadPermission = false;

            String nullProjectName = null;
            Project mockProject = mockProject(nullProjectName);
            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission2(authenticationToken, Item.READ));
            assertFalse(acl.hasPermission2(authenticationToken, Item.DISCOVER));
            assertFalse(acl.hasPermission2(authenticationToken, Item.BUILD));
            assertFalse(acl.hasPermission2(authenticationToken, Item.CONFIGURE));
            assertFalse(acl.hasPermission2(authenticationToken, Item.DELETE));
            assertFalse(acl.hasPermission2(authenticationToken, Item.EXTENDED_READ));
            assertFalse(acl.hasPermission2(authenticationToken, Item.CANCEL));
        }
    }

    @Test
    void testCannotReadRepositoryWithInvalidRepoUrl() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            GHMyself me = mockGHMyselfAs(mockedGitHubBuilder, "Me");
            // private repo I have pull rights to
            GHRepository repo = mockRepository("some-org/a-repo", false, false, false, true);
            mockReposFor(me, Collections.singletonList(repo));
            String invalidRepoUrl = "git@github.com//some-org/a-repo.git";
            Project mockProject = mockProject(invalidRepoUrl);
            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission2(authenticationToken, Item.READ));
        }
    }

    @Test
    void testAgentUserCanCreateConnectAndConfigureAgents() {
        GithubAuthenticationToken authenticationToken = Mockito.mock(GithubAuthenticationToken.class);
        Mockito.when(authenticationToken.isAuthenticated()).thenReturn(true);
        Mockito.when(authenticationToken.getName()).thenReturn("agent");
        GithubRequireOrganizationMembershipACL acl = createACL();

        assertTrue(acl.hasPermission2(authenticationToken, Computer.CREATE));
        assertTrue(acl.hasPermission2(authenticationToken, Computer.CONFIGURE));
        assertTrue(acl.hasPermission2(authenticationToken, Computer.CONNECT));
    }

    @Test
    void testAuthenticatedCanNotCreateConnectAndConfigureAgents() {
        GithubAuthenticationToken authenticationToken = Mockito.mock(GithubAuthenticationToken.class);
        Mockito.when(authenticationToken.isAuthenticated()).thenReturn(true);
        Mockito.when(authenticationToken.getName()).thenReturn("authenticated");
        GithubRequireOrganizationMembershipACL acl = createACL();

        assertFalse(acl.hasPermission2(authenticationToken, Computer.CREATE));
        assertFalse(acl.hasPermission2(authenticationToken, Computer.CONFIGURE));
        assertFalse(acl.hasPermission2(authenticationToken, Computer.CONNECT));
    }

    @Test
    void testAnonymousCanViewJobStatusWhenGranted() {
        this.allowAnonymousJobStatusPermission = true;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertTrue(acl.hasPermission2(ANONYMOUS_USER, VIEW_JOBSTATUS_PERMISSION));
    }

    @Test
    void testAnonymousCannotViewJobStatusWhenNotGranted() {
        this.allowAnonymousJobStatusPermission = false;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertFalse(acl.hasPermission2(ANONYMOUS_USER, VIEW_JOBSTATUS_PERMISSION));
    }

    @Test
    void testAnonymousCanReachWebhookWhenGranted() {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<Stapler> mockedStapler = Mockito.mockStatic(Stapler.class)) {
            mockJenkins(mockedJenkins);
            this.allowAnonymousWebhookPermission = true;

            StaplerRequest2 currentRequest = Mockito.mock(StaplerRequest2.class);
            mockedStapler.when(Stapler::getCurrentRequest2).thenReturn(currentRequest);
            Mockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/github-webhook/");

            GithubRequireOrganizationMembershipACL acl = createACL();

            assertTrue(acl.hasPermission2(ANONYMOUS_USER, Item.READ));
        }
    }

    @Test
    void testAnonymousCannotReachWebhookIfNotGranted() {
        try (MockedStatic<Stapler> mockedStapler = Mockito.mockStatic(Stapler.class)) {
            this.allowAnonymousWebhookPermission = false;

            StaplerRequest2 currentRequest = Mockito.mock(StaplerRequest2.class);
            mockedStapler.when(Stapler::getCurrentRequest2).thenReturn(currentRequest);
            Mockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/github-webhook/");

            GithubRequireOrganizationMembershipACL acl = createACL();

            assertFalse(acl.hasPermission2(ANONYMOUS_USER, Item.READ));
        }
    }

    @Test
    void testAnonymousCanReadAndDiscoverWhenGranted() {
        this.allowAnonymousReadPermission = true;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertTrue(acl.hasPermission2(ANONYMOUS_USER, Item.READ));
        assertTrue(acl.hasPermission2(ANONYMOUS_USER, Item.DISCOVER));
    }

    @Test
    void testAnonymousCantReadAndDiscoverWhenNotGranted() {
        this.allowAnonymousReadPermission = false;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertFalse(acl.hasPermission2(ANONYMOUS_USER, Item.READ));
        assertFalse(acl.hasPermission2(ANONYMOUS_USER, Item.DISCOVER));
    }

    @Test
    void testAnonymousCanReachCCTrayWhenGranted() {
        try (MockedStatic<Stapler> mockedStapler = Mockito.mockStatic(Stapler.class)) {
            this.allowAnonymousCCTrayPermission = true;

            StaplerRequest2 currentRequest = Mockito.mock(StaplerRequest2.class);
            mockedStapler.when(Stapler::getCurrentRequest2).thenReturn(currentRequest);
            Mockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/cc.xml");

            GithubRequireOrganizationMembershipACL acl = createACL();

            assertTrue(acl.hasPermission2(ANONYMOUS_USER, Item.READ));
        }
    }

    @Test
    void testAnonymousCannotReachCCTrayIfNotGranted() {
        try (MockedStatic<Stapler> mockedStapler = Mockito.mockStatic(Stapler.class)) {
            this.allowAnonymousCCTrayPermission = false;

            StaplerRequest2 currentRequest = Mockito.mock(StaplerRequest2.class);
            mockedStapler.when(Stapler::getCurrentRequest2).thenReturn(currentRequest);
            Mockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/cc.xml");

            GithubRequireOrganizationMembershipACL acl = createACL();

            assertFalse(acl.hasPermission2(ANONYMOUS_USER, Item.READ));
        }
    }
}
