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
@PrepareForTest({GitHub.class, GitHubBuilder.class, Jenkins.class, GithubSecurityRealm.class, WorkflowJob.class})
public class GithubRequireOrganizationMembershipACLTest extends TestCase {

    @Mock
    private Jenkins jenkins;

    private GitHub gh;

    @Mock
    private GithubSecurityRealm securityRealm;

    @Before
    public void setUp() throws Exception {
        //GithubSecurityRealm myRealm = PowerMockito.mock(GithubSecurityRealm.class);
        PowerMockito.mockStatic(Jenkins.class);
        PowerMockito.when(Jenkins.getInstance()).thenReturn(jenkins);
        PowerMockito.when(jenkins.getSecurityRealm()).thenReturn(securityRealm);
        PowerMockito.when(securityRealm.getOauthScopes()).thenReturn("read:org,repo");
        PowerMockito.when(securityRealm.hasScope("read:org")).thenReturn(true);
        PowerMockito.when(securityRealm.hasScope("repo")).thenReturn(true);
    }

    private static final Permission VIEW_JOBSTATUS_PERMISSION = new Permission(Item.PERMISSIONS,
            "ViewStatus",
            Messages._Item_READ_description(),
            Permission.READ,
            PermissionScope.ITEM);
    private final Authentication ANONYMOUS_USER        = new AnonymousAuthenticationToken("anonymous",
            "anonymous",
            new GrantedAuthority[]{new GrantedAuthorityImpl("anonymous")});

    boolean allowAnonymousJobStatusPermission = false;

    private GithubRequireOrganizationMembershipACL aclForProject(Project project) {
        boolean useRepositoryPermissions = true;
        boolean authenticatedUserReadPermission = true;
        boolean authenticatedUserCreateJobPermission = false;

        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL(
                "admin",
                "myOrg",
                authenticatedUserReadPermission,
                useRepositoryPermissions,
                authenticatedUserCreateJobPermission,
                true,
                true,
                true,
                allowAnonymousJobStatusPermission);
        return acl.cloneForProject(project);
    }

    private GithubRequireOrganizationMembershipACL aclForMultiBranchProject(MultiBranchProject multiBranchProject) {
        boolean useRepositoryPermissions = true;
        boolean authenticatedUserReadPermission = true;
        boolean authenticatedUserCreateJobPermission = false;

        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL(
            "admin",
            "myOrg",
            authenticatedUserReadPermission,
            useRepositoryPermissions,
            authenticatedUserCreateJobPermission,
            true,
            true,
            true,
            allowAnonymousJobStatusPermission);
        return acl.cloneForProject(multiBranchProject);
    }

    private GithubRequireOrganizationMembershipACL aclForWorkflowJob(WorkflowJob workflowJob) {
        boolean useRepositoryPermissions = true;
        boolean authenticatedUserReadPermission = true;
        boolean authenticatedUserCreateJobPermission = false;

        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL(
            "admin",
            "myOrg",
            authenticatedUserReadPermission,
            useRepositoryPermissions,
            authenticatedUserCreateJobPermission,
            true,
            true,
            true,
            allowAnonymousJobStatusPermission);
        return acl.cloneForProject(workflowJob);
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
        return me;
    }

    private void mockReposFor(GHPerson person, List<String> repositoryNames) throws IOException {
        List<GHRepository> repositories = repositoryListOf(repositoryNames);
        PagedIterable<GHRepository> pagedRepositories = PowerMockito.mock(PagedIterable.class);
        PowerMockito.when(person.listRepositories()).thenReturn(pagedRepositories);
        PowerMockito.when(pagedRepositories.asList()).thenReturn(repositories);
    };

    private void mockOrgRepos(GHMyself me, Map<String, List<String>> orgsAndRepoNames) throws IOException {
        Set<GHOrganization> organizations = new HashSet();
        Set<String> organizationNames = orgsAndRepoNames.keySet();
        for (String organizationName : organizationNames) {
            List<String> repositories = orgsAndRepoNames.get(organizationName);
            organizations.add(mockGHOrganization(organizationName, repositories));
        }
        GHPersonSet organizationSet = new GHPersonSet(organizations);
        PowerMockito.when(me.getAllOrganizations()).thenReturn(organizationSet);
    }

    private List<GHRepository> repositoryListOf(List<String> repositoryNames) throws IOException {
        List<GHRepository> repositoriesSet = new ArrayList<GHRepository>();
        for (String repositoryName : repositoryNames) {
            String[] parts = repositoryName.split("/");
            GHRepository repository = mockGHRepository(parts[0], parts[1]);
            repositoriesSet.add(repository);
        }
        return repositoriesSet;
    }

    private GHRepository mockGHRepository(String ownerName, String name) throws IOException {
        GHRepository ghRepository = PowerMockito.mock(GHRepository.class);
        GHUser ghUser = PowerMockito.mock(GHUser.class);
        PowerMockito.when(ghUser.getLogin()).thenReturn(ownerName);
        PowerMockito.when(ghRepository.getOwner()).thenReturn(ghUser);
        PowerMockito.when(ghRepository.getName()).thenReturn(name);
        return ghRepository;
    }

    private GHOrganization mockGHOrganization(String organizationName, List<String> repositories) throws IOException {
        GHOrganization ghOrganization = PowerMockito.mock(GHOrganization.class);
        mockReposFor(ghOrganization, repositories);
        return ghOrganization;
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

    @Test
    public void testCanReadAndBuildOneOfMyRepositories() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
        mockReposFor(me, Arrays.asList("me/a-repo"));
        mockOrgRepos(me, ImmutableMap.of("some-org", Arrays.asList("some-org/a-public-repo")));
        String repoUrl = "https://github.com/me/a-repo.git";
        Project mockProject = mockProject(repoUrl);
        MultiBranchProject mockMultiBranchProject = mockMultiBranchProject(repoUrl);
        WorkflowJob mockWorkflowJob = mockWorkflowJob(repoUrl);
        GithubRequireOrganizationMembershipACL workflowJobAcl = aclForWorkflowJob(mockWorkflowJob);
        GithubRequireOrganizationMembershipACL multiBranchProjectAcl = aclForMultiBranchProject(mockMultiBranchProject);
        GithubRequireOrganizationMembershipACL projectAcl = aclForProject(mockProject);
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(projectAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(projectAcl.hasPermission(authenticationToken, Item.BUILD));
        assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.BUILD));
        assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.BUILD));
    }

    @Override
    protected void tearDown() throws Exception {
        gh = null;
        super.tearDown();
        GithubAuthenticationToken.clearCaches();
    }

    @Test
    public void testCanReadAndBuildOrgRepositoryICollaborateOn() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
        mockReposFor(me, Arrays.asList("me/a-repo"));
        mockOrgRepos(me, ImmutableMap.of("some-org", Arrays.asList("some-org/a-private-repo")));
        String repoUrl = "https://github.com/some-org/a-private-repo.git";
        Project mockProject = mockProject(repoUrl);
        MultiBranchProject mockMultiBranchProject = mockMultiBranchProject(repoUrl);
        WorkflowJob mockWorkflowJob = mockWorkflowJob(repoUrl);
        GithubRequireOrganizationMembershipACL workflowJobAcl = aclForWorkflowJob(mockWorkflowJob);
        GithubRequireOrganizationMembershipACL multiBranchProjectAcl = aclForMultiBranchProject(mockMultiBranchProject);
        GithubRequireOrganizationMembershipACL projectAcl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(projectAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(projectAcl.hasPermission(authenticationToken, Item.BUILD));
        assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.BUILD));
        assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.BUILD));
    }

    @Test
    public void testCanReadAndBuildOtherOrgPrivateRepositoryICollaborateOn() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
        mockReposFor(me, Arrays.asList("me/a-repo"));
        mockOrgRepos(me, ImmutableMap.of("some-org", Arrays.asList("some-org/a-private-repo")));
        GHRepository ghRepository = PowerMockito.mock(GHRepository.class);
        PowerMockito.when(gh.getRepository("org-i-dont-belong-to/a-private-repo-i-collaborate-on")).thenReturn(ghRepository);
        PowerMockito.when(ghRepository.isPrivate()).thenReturn(true);
        PowerMockito.when(ghRepository.hasAdminAccess()).thenReturn(false);
        PowerMockito.when(ghRepository.hasPushAccess()).thenReturn(false);
        PowerMockito.when(ghRepository.hasPullAccess()).thenReturn(true);

        // The user isn't part of "org-i-dont-belong-to"
        String repoUrl = "https://github.com/org-i-dont-belong-to/a-private-repo-i-collaborate-on.git";
        Project mockProject = mockProject(repoUrl);
        MultiBranchProject mockMultiBranchProject = mockMultiBranchProject(repoUrl);
        WorkflowJob mockWorkflowJob = mockWorkflowJob(repoUrl);
        GithubRequireOrganizationMembershipACL workflowJobAcl = aclForWorkflowJob(mockWorkflowJob);
        GithubRequireOrganizationMembershipACL multiBranchProjectAcl = aclForMultiBranchProject(mockMultiBranchProject);
        GithubRequireOrganizationMembershipACL projectAcl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(projectAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(projectAcl.hasPermission(authenticationToken, Item.BUILD));
        assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(multiBranchProjectAcl.hasPermission(authenticationToken, Item.BUILD));
        assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.READ));
        assertTrue(workflowJobAcl.hasPermission(authenticationToken, Item.BUILD));
    }

    @Test
    public void testCanNotReadOrBuildRepositoryIDoNotCollaborateOn() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
        mockReposFor(me, Arrays.asList("me/a-repo"));
        mockOrgRepos(me, ImmutableMap.of("some-org", Arrays.asList("some-org/a-private-repo")));
        String repoUrl = "https://github.com/some-org/another-private-repo.git";
        Project mockProject = mockProject(repoUrl);
        MultiBranchProject mockMultiBranchProject = mockMultiBranchProject(repoUrl);
        WorkflowJob mockWorkflowJob = mockWorkflowJob(repoUrl);
        GithubRequireOrganizationMembershipACL workflowJobAcl = aclForWorkflowJob(mockWorkflowJob);
        GithubRequireOrganizationMembershipACL multiBranchProjectAcl = aclForMultiBranchProject(mockMultiBranchProject);
        GithubRequireOrganizationMembershipACL projectAcl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(projectAcl.hasPermission(authenticationToken, Item.READ));
        assertFalse(projectAcl.hasPermission(authenticationToken, Item.BUILD));
        assertFalse(multiBranchProjectAcl.hasPermission(authenticationToken, Item.READ));
        assertFalse(multiBranchProjectAcl.hasPermission(authenticationToken, Item.BUILD));
        assertFalse(workflowJobAcl.hasPermission(authenticationToken, Item.READ));
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
    }

    @Test
    public void testNotGrantedBuildWhenRepositoryIsEmpty() throws IOException {
        mockGHMyselfAs("Me");
        Project mockProject = mockProject(null);
        GithubRequireOrganizationMembershipACL acl = aclForProject(mockProject);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
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
    }

    @Test
    public void testGlobalReadAvailableDueToAuthenticatedUserReadPermission() throws IOException {
        boolean useRepositoryPermissions = false;
        boolean authenticatedUserReadPermission = true;
        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                authenticatedUserReadPermission, useRepositoryPermissions, true, true, true, true, false);
        Project mockProject = mockProject("https://github.com/some-org/another-private-repo.git");
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Hudson.READ));

    }

    @Test
    public void testWithoutUseRepositoryPermissionsSetCanReadDueToAuthenticatedUserReadPermission() throws IOException {
        boolean useRepositoryPermissions = false;
        boolean authenticatedUserReadPermission = true;
        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                authenticatedUserReadPermission, useRepositoryPermissions, true, true, true, true, false);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testWithoutUseRepositoryPermissionsSetCannotReadWithoutToAuthenticatedUserReadPermission() throws IOException {
        boolean useRepositoryPermissions = false;
        boolean authenticatedUserReadPermission = false;
        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                authenticatedUserReadPermission, useRepositoryPermissions, true, true, true, true, false);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
    }

    @Test
    public void testUsersCannotCreateWithoutConfigurationEnabledPermission() throws IOException {
        boolean authenticatedUserCreateJobPermission = false;
        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, true, true, true, false);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.CREATE));
    }

    @Test
    public void testUsersCanCreateWithConfigurationEnabledPermission() throws IOException {
        boolean authenticatedUserCreateJobPermission = true;
        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL acl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, true, true, true, false);

        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.CREATE));
    }

    @Test
    public void testCanReadConfigureDeleteAProjectWithAuthenticatedUserReadPermission() throws IOException {
        String nullProjectName = null;
        Project mockProject = mockProject(nullProjectName);
        boolean authenticatedUserCreateJobPermission = true;
        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL globalAcl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, true, true, true, false);
        GithubRequireOrganizationMembershipACL acl = globalAcl.cloneForProject(mockProject);
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertTrue(acl.hasPermission(authenticationToken, Item.READ));
        assertTrue(acl.hasPermission(authenticationToken, Item.CONFIGURE));
        assertTrue(acl.hasPermission(authenticationToken, Item.DELETE));
        assertTrue(acl.hasPermission(authenticationToken, Item.EXTENDED_READ));
        assertTrue(acl.hasPermission(authenticationToken, Item.CANCEL));
    }

    @Test
    public void testCannotReadConfigureDeleteAProjectWithoutToAuthenticatedUserReadPermission() throws IOException {
        String nullProjectName = null;
        Project mockProject = mockProject(nullProjectName);
        boolean authenticatedUserCreateJobPermission = false;
        mockGHMyselfAs("Me");
        GithubRequireOrganizationMembershipACL globalAcl = new GithubRequireOrganizationMembershipACL("admin", "myOrg",
                true, true, authenticatedUserCreateJobPermission, true, true, true, false);
        GithubRequireOrganizationMembershipACL acl = globalAcl.cloneForProject(mockProject);
        GithubAuthenticationToken authenticationToken = new GithubAuthenticationToken("accessToken", "https://api.github.com");

        assertFalse(acl.hasPermission(authenticationToken, Item.READ));
        assertFalse(acl.hasPermission(authenticationToken, Item.CONFIGURE));
        assertFalse(acl.hasPermission(authenticationToken, Item.DELETE));
        assertFalse(acl.hasPermission(authenticationToken, Item.EXTENDED_READ));
        assertFalse(acl.hasPermission(authenticationToken, Item.CANCEL));
    }

    @Test
    public void testCannotReadRepositoryWithInvalidRepoUrl() throws IOException {
        GHMyself me = mockGHMyselfAs("Me");
        mockReposFor(me, Arrays.asList("me/a-repo"));
        mockOrgRepos(me, ImmutableMap.of("some-org", Arrays.asList("some-org/a-repo")));
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

}
