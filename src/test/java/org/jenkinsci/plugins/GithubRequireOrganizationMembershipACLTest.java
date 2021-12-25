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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.multibranch.BranchJobProperty;
import org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHPerson;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.PagedIterable;
import org.kohsuke.github.RateLimitHandler;
import org.kohsuke.github.extras.okhttp3.OkHttpGitHubConnector;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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

/**
 *
 * @author alex
 */
public class GithubRequireOrganizationMembershipACLTest {

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

    private AutoCloseable closeable;

    @Before
    public void setUp() {
        // default to: use repository permissions; don't allow anonymous read/view status; don't allow authenticated read/create
        allowAnonymousReadPermission = false;
        allowAnonymousJobStatusPermission = false;
        useRepositoryPermissions = true;
        authenticatedUserReadPermission = false;
        authenticatedUserCreateJobPermission = false;
        allowAnonymousWebhookPermission = false;
        allowAnonymousCCTrayPermission = false;

        closeable = MockitoAnnotations.openMocks(this);

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
    private final Authentication ANONYMOUS_USER = new AnonymousAuthenticationToken("anonymous",
            "anonymous",
            new GrantedAuthority[]{new GrantedAuthorityImpl("anonymous")});

    private GithubRequireOrganizationMembershipACL createACL() {
        return new GithubRequireOrganizationMembershipACL(
                "admin",
                "myOrg",
                authenticatedUserReadPermission,
                useRepositoryPermissions,
                authenticatedUserCreateJobPermission,
                allowAnonymousWebhookPermission,
                allowAnonymousCCTrayPermission,
                allowAnonymousReadPermission,
                allowAnonymousJobStatusPermission);
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

    private void mockReposFor(GHPerson person, List<GHRepository> repositories) {
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

    private Project mockProject(String url) {
        Project project = Mockito.mock(Project.class);
        GitSCM gitSCM = Mockito.mock(GitSCM.class);
        UserRemoteConfig userRemoteConfig = Mockito.mock(UserRemoteConfig.class);
        List<UserRemoteConfig> userRemoteConfigs = Collections.singletonList(userRemoteConfig);
        Mockito.when(project.getScm()).thenReturn(gitSCM);
        Mockito.when(gitSCM.getUserRemoteConfigs()).thenReturn(userRemoteConfigs);
        Mockito.when(userRemoteConfig.getUrl()).thenReturn(url);
        return project;
    }

    private WorkflowJob mockWorkflowJob(String url) {
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

    private MultiBranchProject mockMultiBranchProject(String url) {
        WorkflowMultiBranchProject multiBranchProject = Mockito.mock(WorkflowMultiBranchProject.class);
        GitHubSCMSource gitHubSCM = Mockito.mock(GitHubSCMSource.class);
        ArrayList<SCMSource> scmSources = new ArrayList<>();
        scmSources.add(gitHubSCM);
        Mockito.when(multiBranchProject.getSCMSources()).thenReturn(scmSources);
        Mockito.when(gitHubSCM.getRemote()).thenReturn(url);
        return multiBranchProject;
    }

    @After
    public void tearDown() throws Exception {
        closeable.close();
        gh = null;
        GithubAuthenticationToken.clearCaches();
    }

    @Test
    public void testCanReadAndBuildOneOfMyPrivateRepositories() throws IOException {
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

            assertTrue(projectAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(projectAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(projectAcl.hasPermission(authenticationToken, Item.BUILD));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.BUILD));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.BUILD));
        }
    }

    @Test
    public void testCanReadAndBuildAPublicRepository() throws IOException {
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

            assertTrue(projectAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(projectAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(projectAcl.hasPermission(authenticationToken, Item.BUILD));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.BUILD));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.BUILD));
        }
    }

    @Test
    public void testCanReadAndBuildPrivateRepositoryIHavePullRightsOn() throws IOException {
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

            assertTrue(projectAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(projectAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(projectAcl.hasPermission(authenticationToken, Item.BUILD));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.BUILD));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.READ));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.BUILD));
        }
    }

    @Test
    public void testCanNotReadOrBuildRepositoryIDoNotCollaborateOn() throws IOException {
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

            assertFalse(projectAcl.hasPermission(authenticationToken, Item.READ));
            assertFalse(projectAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertFalse(projectAcl.hasPermission(authenticationToken, Item.BUILD));
            assertFalse(multiBranchProjectAcl.hasPermission(authenticationToken, Item.READ));
            assertFalse(multiBranchProjectAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertFalse(multiBranchProjectAcl.hasPermission(authenticationToken, Item.BUILD));
            assertFalse(workflowJobAcl.hasPermission(authenticationToken, Item.READ));
            assertFalse(workflowJobAcl.hasPermission(authenticationToken, Item.DISCOVER));
            assertFalse(workflowJobAcl.hasPermission(authenticationToken, Item.BUILD));
        }
    }

    @Test
    public void testNotGrantedBuildWhenNotUsingGitSCM() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            Project mockProject = Mockito.mock(Project.class);
            Mockito.when(mockProject.getScm()).thenReturn(new NullSCM());

            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission(authenticationToken, Item.READ));
            assertFalse(acl.hasPermission(authenticationToken, Item.DISCOVER));
        }
    }

    @Test
    public void testNotGrantedBuildWhenRepositoryIsEmpty() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            Project mockProject = mockProject(null);
            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission(authenticationToken, Item.READ));
            assertFalse(acl.hasPermission(authenticationToken, Item.DISCOVER));
        }
    }

    @Test
    public void testNotGrantedReadWhenRepositoryUrlIsEmpty() throws IOException {
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

            assertFalse(acl.hasPermission(authenticationToken, Item.READ));
            assertFalse(acl.hasPermission(authenticationToken, Item.DISCOVER));
        }
    }

    @Test
    public void testGlobalReadAvailableDueToAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.useRepositoryPermissions = false;
            this.authenticatedUserReadPermission = true;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(acl.hasPermission(authenticationToken, Hudson.READ));
        }
    }

    @Test
    public void testWithoutUseRepositoryPermissionsSetCanReadDueToAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.useRepositoryPermissions = false;
            this.authenticatedUserReadPermission = true;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(acl.hasPermission(authenticationToken, Item.READ));
        }
    }

    @Test
    public void testWithoutUseRepositoryPermissionsSetCannotReadWithoutAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.useRepositoryPermissions = false;
            this.authenticatedUserReadPermission = false;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        }
    }

    @Test
    public void testUsersCannotCreateWithoutConfigurationEnabledPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.authenticatedUserCreateJobPermission = false;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission(authenticationToken, Item.CREATE));
        }
    }

    @Test
    public void testUsersCanCreateWithConfigurationEnabledPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.authenticatedUserCreateJobPermission = true;

            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = createACL();
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertTrue(acl.hasPermission(authenticationToken, Item.CREATE));
        }
    }

    @Test
    public void testCanReadAProjectWithAuthenticatedUserReadPermission() throws IOException {
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
            assertTrue(acl.hasPermission(authenticationToken, Item.READ));
            assertTrue(acl.hasPermission(authenticationToken, Item.DISCOVER));
            // but not to build, cancel, configure, view configuration, delete it
            assertFalse(acl.hasPermission(authenticationToken, Item.BUILD));
            assertFalse(acl.hasPermission(authenticationToken, Item.CONFIGURE));
            assertFalse(acl.hasPermission(authenticationToken, Item.DELETE));
            assertFalse(acl.hasPermission(authenticationToken, Item.EXTENDED_READ));
            assertFalse(acl.hasPermission(authenticationToken, Item.CANCEL));
        }
    }

    @Test
    public void testCannotReadAProjectWithoutAuthenticatedUserReadPermission() throws IOException {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<GitHubBuilder> mockedGitHubBuilder = Mockito.mockStatic(GitHubBuilder.class)) {
            mockJenkins(mockedJenkins);
            this.authenticatedUserReadPermission = false;

            String nullProjectName = null;
            Project mockProject = mockProject(nullProjectName);
            mockGHMyselfAs(mockedGitHubBuilder, "Me");
            GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);
            GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

            assertFalse(acl.hasPermission(authenticationToken, Item.READ));
            assertFalse(acl.hasPermission(authenticationToken, Item.DISCOVER));
            assertFalse(acl.hasPermission(authenticationToken, Item.BUILD));
            assertFalse(acl.hasPermission(authenticationToken, Item.CONFIGURE));
            assertFalse(acl.hasPermission(authenticationToken, Item.DELETE));
            assertFalse(acl.hasPermission(authenticationToken, Item.EXTENDED_READ));
            assertFalse(acl.hasPermission(authenticationToken, Item.CANCEL));
        }
    }

    @Test
    public void testCannotReadRepositoryWithInvalidRepoUrl() throws IOException {
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

            assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        }
    }

    @Test
    public void testAnonymousCanViewJobStatusWhenGranted() {
        this.allowAnonymousJobStatusPermission = true;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertTrue(acl.hasPermission(ANONYMOUS_USER, VIEW_JOBSTATUS_PERMISSION));
    }

    @Test
    public void testAnonymousCannotViewJobStatusWhenNotGranted() {
        this.allowAnonymousJobStatusPermission = false;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertFalse(acl.hasPermission(ANONYMOUS_USER, VIEW_JOBSTATUS_PERMISSION));
    }

    @Test
    public void testAnonymousCanReachWebhookWhenGranted() {
        try (MockedStatic<Jenkins> mockedJenkins = Mockito.mockStatic(Jenkins.class);
             MockedStatic<Stapler> mockedStapler = Mockito.mockStatic(Stapler.class)) {
            mockJenkins(mockedJenkins);
            this.allowAnonymousWebhookPermission = true;

            StaplerRequest currentRequest = Mockito.mock(StaplerRequest.class);
            mockedStapler.when(Stapler::getCurrentRequest).thenReturn(currentRequest);
            Mockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/github-webhook/");

            GithubRequireOrganizationMembershipACL acl = createACL();

            assertTrue(acl.hasPermission(ANONYMOUS_USER, Item.READ));
        }
    }

    @Test
    public void testAnonymousCannotReachWebhookIfNotGranted() {
        try (MockedStatic<Stapler> mockedStapler = Mockito.mockStatic(Stapler.class)) {
            this.allowAnonymousWebhookPermission = false;

            StaplerRequest currentRequest = Mockito.mock(StaplerRequest.class);
            mockedStapler.when(Stapler::getCurrentRequest).thenReturn(currentRequest);
            Mockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/github-webhook/");

            GithubRequireOrganizationMembershipACL acl = createACL();

            assertFalse(acl.hasPermission(ANONYMOUS_USER, Item.READ));
        }
    }

    @Test
    public void testAnonymousCanReadAndDiscoverWhenGranted() {
        this.allowAnonymousReadPermission = true;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertTrue(acl.hasPermission(ANONYMOUS_USER, Item.READ));
        assertTrue(acl.hasPermission(ANONYMOUS_USER, Item.DISCOVER));
    }

    @Test
    public void testAnonymousCantReadAndDiscoverWhenNotGranted() {
        this.allowAnonymousReadPermission = false;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertFalse(acl.hasPermission(ANONYMOUS_USER, Item.READ));
        assertFalse(acl.hasPermission(ANONYMOUS_USER, Item.DISCOVER));
    }

    @Test
    public void testAnonymousCanReachCCTrayWhenGranted() {
        try (MockedStatic<Stapler> mockedStapler = Mockito.mockStatic(Stapler.class)) {
            this.allowAnonymousCCTrayPermission = true;

            StaplerRequest currentRequest = Mockito.mock(StaplerRequest.class);
            mockedStapler.when(Stapler::getCurrentRequest).thenReturn(currentRequest);
            Mockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/cc.xml");

            GithubRequireOrganizationMembershipACL acl = createACL();

            assertTrue(acl.hasPermission(ANONYMOUS_USER, Item.READ));
        }
    }

    @Test
    public void testAnonymousCannotReachCCTrayIfNotGranted() {
        try (MockedStatic<Stapler> mockedStapler = Mockito.mockStatic(Stapler.class)) {
            this.allowAnonymousCCTrayPermission = false;

            StaplerRequest currentRequest = Mockito.mock(StaplerRequest.class);
            mockedStapler.when(Stapler::getCurrentRequest).thenReturn(currentRequest);
            Mockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/cc.xml");

            GithubRequireOrganizationMembershipACL acl = createACL();

            assertFalse(acl.hasPermission(ANONYMOUS_USER, Item.READ));
        }
    }

}
