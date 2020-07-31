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

import com.google.common.collect.ImmutableMap;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.multibranch.BranchJobProperty;
import org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHPerson;
import org.kohsuke.github.GHPersonSet;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.PagedIterable;
import org.kohsuke.github.RateLimitHandler;
import org.kohsuke.github.extras.OkHttpConnector;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
@RunWith(PowerMockRunner.class)
@PrepareForTest({GitHub.class, GitHubBuilder.class, Jenkins.class, GithubSecurityRealm.class, WorkflowJob.class, Stapler.class})
public class GithubRequireOrganizationMembershipACLTest extends TestCase {

    @Mock
    private Jenkins jenkins;

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

    @Before
    public void setUp() throws Exception {
        // default to: use repository permissions; don't allow anonymous read/view status; don't allow authenticated read/create
        allowAnonymousReadPermission = false;
        allowAnonymousJobStatusPermission = false;
        useRepositoryPermissions = true;
        authenticatedUserReadPermission = false;
        authenticatedUserCreateJobPermission = false;
        allowAnonymousWebhookPermission = false;
        allowAnonymousCCTrayPermission = false;

        //GithubSecurityRealm myRealm = PowerMockito.mock(GithubSecurityRealm.class);
        PowerMockito.mockStatic(Jenkins.class);
        PowerMockito.when(Jenkins.getInstance()).thenReturn(jenkins);
        PowerMockito.when(jenkins.getSecurityRealm()).thenReturn(securityRealm);
        PowerMockito.when(jenkins.getRootUrl()).thenReturn("https://www.jenkins.org/");
        PowerMockito.when(securityRealm.getOauthScopes()).thenReturn("read:org,repo");
        PowerMockito.when(securityRealm.hasScope("read:org")).thenReturn(true);
        PowerMockito.when(securityRealm.hasScope("repo")).thenReturn(true);
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

    private GHMyself mockGHMyselfAs(String username) throws IOException {
        gh = PowerMockito.mock(GitHub.class);
        GitHubBuilder builder = PowerMockito.mock(GitHubBuilder.class);
        PowerMockito.mockStatic(GitHub.class);
        PowerMockito.mockStatic(GitHubBuilder.class);
        PowerMockito.when(GitHubBuilder.fromEnvironment()).thenReturn(builder);
        PowerMockito.when(builder.withEndpoint("https://api.github.com")).thenReturn(builder);
        PowerMockito.when(builder.withOAuthToken("accessToken")).thenReturn(builder);
        PowerMockito.when(builder.withRateLimitHandler(RateLimitHandler.FAIL)).thenReturn(builder);
        PowerMockito.when(builder.withConnector(Mockito.any(OkHttpConnector.class))).thenReturn(builder);
        PowerMockito.when(builder.build()).thenReturn(gh);
        GHMyself me = PowerMockito.mock(GHMyself.class);
        PowerMockito.when(gh.getMyself()).thenReturn((GHMyself) me);
        PowerMockito.when(me.getLogin()).thenReturn(username);
        mockReposFor(me, Collections.<GHRepository>emptyList());
        return me;
    }

    // TODO: Add ability to set list of orgs user belongs to to check whitelisting!

    private void mockReposFor(GHPerson person, List<GHRepository> repositories) throws IOException {
        PagedIterable<GHRepository> pagedRepositories = PowerMockito.mock(PagedIterable.class);
        PowerMockito.when(person.listRepositories(100)).thenReturn(pagedRepositories);
        PowerMockito.when(pagedRepositories.asList()).thenReturn(repositories);
    }

    private GHRepository mockRepository(String repositoryName, boolean isPublic, boolean admin, boolean push, boolean pull) throws IOException {
      GHRepository ghRepository = PowerMockito.mock(GHRepository.class);
      PowerMockito.when(gh.getRepository(repositoryName)).thenReturn(ghRepository);
      PowerMockito.when(ghRepository.isPrivate()).thenReturn(!isPublic);
      PowerMockito.when(ghRepository.hasAdminAccess()).thenReturn(admin);
      PowerMockito.when(ghRepository.hasPushAccess()).thenReturn(push);
      PowerMockito.when(ghRepository.hasPullAccess()).thenReturn(pull);
      PowerMockito.when(ghRepository.getFullName()).thenReturn(repositoryName);
      return ghRepository;
    }

    private GHRepository mockPublicRepository(String repositoryName) throws IOException {
      return mockRepository(repositoryName, true, false, false, false);
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

    private WorkflowJob mockWorkflowJob(String url) {
        WorkflowJob project = PowerMockito.mock(WorkflowJob.class);
        GitSCM gitSCM = PowerMockito.mock(GitSCM.class);
        Branch branch = PowerMockito.mock(Branch.class);
        BranchJobProperty branchJobProperty = PowerMockito.mock(BranchJobProperty.class);
        UserRemoteConfig userRemoteConfig = PowerMockito.mock(UserRemoteConfig.class);
        List<UserRemoteConfig> userRemoteConfigs = Arrays.asList(userRemoteConfig);
        PowerMockito.when(project.getProperty(BranchJobProperty.class)).thenReturn(branchJobProperty);
        PowerMockito.when(branchJobProperty.getBranch()).thenReturn(branch);
        PowerMockito.when(branch.getScm()).thenReturn(gitSCM);
        PowerMockito.when(gitSCM.getUserRemoteConfigs()).thenReturn(userRemoteConfigs);
        PowerMockito.when(userRemoteConfig.getUrl()).thenReturn(url);
        return project;
    }

    private MultiBranchProject mockMultiBranchProject(String url) {
        WorkflowMultiBranchProject multiBranchProject = PowerMockito.mock(WorkflowMultiBranchProject.class);
        GitHubSCMSource gitHubSCM = PowerMockito.mock(GitHubSCMSource.class);
        ArrayList<SCMSource> scmSources = new ArrayList<SCMSource>();
        scmSources.add(gitHubSCM);
        PowerMockito.when(multiBranchProject.getSCMSources()).thenReturn(scmSources);
        PowerMockito.when(gitHubSCM.getRemote()).thenReturn(url);
        return multiBranchProject;
    }

    @Override
    protected void tearDown() throws Exception {
        gh = null;
        super.tearDown();
        GithubAuthenticationToken.clearCaches();
    }

    @Test
    public void testCanReadAndBuildOneOfMyPrivateRepositories() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
        GHRepository repo = mockRepository("me/a-repo", false, true, true, true); // private; admin, push, and pull rights
        mockReposFor(me, Arrays.asList(repo)); // hook to my listing
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

    @Test
    public void testCanReadAndBuildAPublicRepository() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
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

    @Test
    public void testCanReadAndBuildPrivateRepositoryIHavePullRightsOn() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
        // private repo I have pull rights to
        GHRepository repo = mockRepository("some-org/a-private-repo", false, false, false, true);
        mockReposFor(me, Arrays.asList(repo));
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

    @Test
    public void testCanNotReadOrBuildRepositoryIDoNotCollaborateOn() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");

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

    @Test
    public void testNotGrantedBuildWhenNotUsingGitSCM() throws IOException {
        mockGHMyselfAs("Me");
        Project mockProject = PowerMockito.mock(Project.class);
        PowerMockito.when(mockProject.getScm()).thenReturn(new NullSCM());

        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        assertFalse(acl.hasPermission(authenticationToken, Item.DISCOVER));
    }

    @Test
    public void testNotGrantedBuildWhenRepositoryIsEmpty() throws IOException {
        mockGHMyselfAs("Me");
        Project mockProject = mockProject(null);
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        assertFalse(acl.hasPermission(authenticationToken, Item.DISCOVER));
    }

    @Test
    public void testNotGrantedReadWhenRepositoryUrlIsEmpty() throws IOException {
        mockGHMyselfAs("Me");
        Project mockProject = PowerMockito.mock(Project.class);
        PowerMockito.when(mockProject.getScm()).thenReturn(new NullSCM());
        GitSCM gitSCM = PowerMockito.mock(GitSCM.class);
        List<UserRemoteConfig> userRemoteConfigs = Collections.<UserRemoteConfig>emptyList();
        PowerMockito.when(mockProject.getScm()).thenReturn(gitSCM);
        PowerMockito.when(gitSCM.getUserRemoteConfigs()).thenReturn(userRemoteConfigs);

        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        assertFalse(acl.hasPermission(authenticationToken, Item.DISCOVER));
    }

    @Test
    public void testGlobalReadAvailableDueToAuthenticatedUserReadPermission() throws IOException {
        this.useRepositoryPermissions = false;
        this.authenticatedUserReadPermission = true;

        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = createACL();
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Hudson.READ));
    }

    @Test
    public void testWithoutUseRepositoryPermissionsSetCanReadDueToAuthenticatedUserReadPermission() throws IOException {
        this.useRepositoryPermissions = false;
        this.authenticatedUserReadPermission = true;

        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = createACL();
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testWithoutUseRepositoryPermissionsSetCannotReadWithoutAuthenticatedUserReadPermission() throws IOException {
        this.useRepositoryPermissions = false;
        this.authenticatedUserReadPermission = false;

        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = createACL();
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testUsersCannotCreateWithoutConfigurationEnabledPermission() throws IOException {
        this.authenticatedUserCreateJobPermission = false;

        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = createACL();
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.CREATE));
    }

    @Test
    public void testUsersCanCreateWithConfigurationEnabledPermission() throws IOException {
        this.authenticatedUserCreateJobPermission = true;

        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = createACL();
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.CREATE));
    }

    @Test
    public void testCanReadAProjectWithAuthenticatedUserReadPermission() throws IOException {
        this.authenticatedUserReadPermission = true;
        this.useRepositoryPermissions = false;

        String nullProjectName = null;
        Project mockProject = mockProject(nullProjectName);
        mockGHMyselfAs("Me");
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

    @Test
    public void testCannotReadAProjectWithoutAuthenticatedUserReadPermission() throws IOException {
        this.authenticatedUserReadPermission = false;

        String nullProjectName = null;
        Project mockProject = mockProject(nullProjectName);
        mockGHMyselfAs("Me");
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

    @Test
    public void testCannotReadRepositoryWithInvalidRepoUrl() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
        // private repo I have pull rights to
        GHRepository repo = mockRepository("some-org/a-repo", false, false, false, true);
        mockReposFor(me, Arrays.asList(repo));
        String invalidRepoUrl = "git@github.com//some-org/a-repo.git";
        Project mockProject = mockProject(invalidRepoUrl);
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testAnonymousCanViewJobStatusWhenGranted() throws IOException {
        this.allowAnonymousJobStatusPermission = true;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertTrue(acl.hasPermission(ANONYMOUS_USER, VIEW_JOBSTATUS_PERMISSION));
    }

    @Test
    public void testAnonymousCannotViewJobStatusWhenNotGranted() throws IOException {
        this.allowAnonymousJobStatusPermission = false;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertFalse(acl.hasPermission(ANONYMOUS_USER, VIEW_JOBSTATUS_PERMISSION));
    }

    @Test
    public void testAnonymousCanReachWebhookWhenGranted() throws IOException {
        this.allowAnonymousWebhookPermission = true;

        StaplerRequest currentRequest = PowerMockito.mock(StaplerRequest.class);
        PowerMockito.mockStatic(Stapler.class);
        PowerMockito.when(Stapler.getCurrentRequest()).thenReturn(currentRequest);
        PowerMockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/github-webhook/");

        GithubRequireOrganizationMembershipACL acl = createACL();

        assertTrue(acl.hasPermission(ANONYMOUS_USER, Item.READ));
    }

    @Test
    public void testAnonymousCannotReachWebhookIfNotGranted() throws IOException {
        this.allowAnonymousWebhookPermission = false;

        StaplerRequest currentRequest = PowerMockito.mock(StaplerRequest.class);
        PowerMockito.mockStatic(Stapler.class);
        PowerMockito.when(Stapler.getCurrentRequest()).thenReturn(currentRequest);
        PowerMockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/github-webhook/");

        GithubRequireOrganizationMembershipACL acl = createACL();

        assertFalse(acl.hasPermission(ANONYMOUS_USER, Item.READ));
    }

    @Test
    public void testAnonymousCanReadAndDiscoverWhenGranted() throws IOException {
        this.allowAnonymousReadPermission = true;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertTrue(acl.hasPermission(ANONYMOUS_USER, Item.READ));
        assertTrue(acl.hasPermission(ANONYMOUS_USER, Item.DISCOVER));
    }

    @Test
    public void testAnonymousCantReadAndDiscoverWhenNotGranted() throws IOException {
        this.allowAnonymousReadPermission = false;

        Project mockProject = mockProject("https://github.com/some-org/a-public-repo.git");
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        assertFalse(acl.hasPermission(ANONYMOUS_USER, Item.READ));
        assertFalse(acl.hasPermission(ANONYMOUS_USER, Item.DISCOVER));
    }

    @Test
    public void testAnonymousCanReachCCTrayWhenGranted() throws IOException {
        this.allowAnonymousCCTrayPermission = true;

        StaplerRequest currentRequest = PowerMockito.mock(StaplerRequest.class);
        PowerMockito.mockStatic(Stapler.class);
        PowerMockito.when(Stapler.getCurrentRequest()).thenReturn(currentRequest);
        PowerMockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/cc.xml");

        GithubRequireOrganizationMembershipACL acl = createACL();

        assertTrue(acl.hasPermission(ANONYMOUS_USER, Item.READ));
    }

    @Test
    public void testAnonymousCannotReachCCTrayIfNotGranted() throws IOException {
        this.allowAnonymousCCTrayPermission = false;

        StaplerRequest currentRequest = PowerMockito.mock(StaplerRequest.class);
        PowerMockito.mockStatic(Stapler.class);
        PowerMockito.when(Stapler.getCurrentRequest()).thenReturn(currentRequest);
        PowerMockito.when(currentRequest.getOriginalRequestURI()).thenReturn("https://www.jenkins.org/cc.xml");

        GithubRequireOrganizationMembershipACL acl = createACL();

        assertFalse(acl.hasPermission(ANONYMOUS_USER, Item.READ));
    }

}
