/**
 The MIT License

Copyright (c) 2011 Michael O'Cleirigh

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

import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.multibranch.BranchJobProperty;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import hudson.model.AbstractItem;
import hudson.model.AbstractProject;
import hudson.model.Describable;
import hudson.model.Item;
import hudson.plugins.git.GitSCM;
import hudson.plugins.git.UserRemoteConfig;
import hudson.security.ACL;
import hudson.security.Permission;
import jenkins.branch.MultiBranchProject;
import jenkins.model.Jenkins;
import jenkins.scm.api.SCMSource;

/**
 * @author Mike
 *
 */
public class GithubRequireOrganizationMembershipACL extends ACL {

    private static final Logger log = Logger
            .getLogger(GithubRequireOrganizationMembershipACL.class.getName());

    private final List<String> organizationNameList;
    private final List<String> adminUserNameList;
    private final boolean authenticatedUserReadPermission;
    private final boolean useRepositoryPermissions;
    private final boolean authenticatedUserCreateJobPermission;
    private final boolean allowGithubWebHookPermission;
    private final boolean allowCcTrayPermission;
    private final boolean allowAnonymousReadPermission;
    private final boolean allowAnonymousJobStatusPermission;
    private final AbstractItem item;

    /*
     * (non-Javadoc)
     *
     * @see hudson.security.ACL#hasPermission(org.acegisecurity.Authentication,
     * hudson.security.Permission)
     */
    @Override
    public boolean hasPermission(@Nonnull Authentication a, @Nonnull Permission permission) {
        if (a instanceof GithubAuthenticationToken) {
            if (!a.isAuthenticated())
                return false;

            GithubAuthenticationToken authenticationToken = (GithubAuthenticationToken) a;

            String candidateName = a.getName();

            if (adminUserNameList.contains(candidateName)) {
                // if they are an admin then they have permission
                log.finest("Granting Admin rights to user " + candidateName);
                return true;
            }

            // Streamline checks!

            // Are they trying to create something and we have that setting enabled? Return quickly!
            if (authenticatedUserCreateJobPermission && permission.equals(Item.CREATE)) {
                return true;
            }

            // Are they trying to read?
            if (checkReadPermission(permission)) {
              // if we support authenticated read return early
              if (authenticatedUserReadPermission) {
                log.finest("Granting Authenticated User read permission to user "
                        + candidateName);
                return true;
              }

              // allow them to read if in whitelisted orgs
              if (isInWhitelistedOrgs(authenticationToken)) { // 1 API call per-user, per-hour
                log.finest("Granting READ rights to user "
                        + candidateName + " as a member of whitelisted organization");
                return true;
              }
              // falls through to try to use repo permissions...
            }
            // allow them to BUILD if in whitelisted orgs
            else if (testBuildPermission(permission) && isInWhitelistedOrgs(authenticationToken)) {  // 1 API call per-user, per-hour
              log.finest("Granting BUILD rights to user "
                      + candidateName + " as a member of whitelisted organization");
              return true;
            }

            // regardless of what permissions they're seeking, use the repo permissions to determine if possible
            if (useRepositoryPermissions && this.item != null) {
              String repositoryName = getRepositoryName();

              if (repositoryName == null) {
                  return false;
              }

              // best case 0 API calls (repo is public and that flag is cached, or user's repo listing is already cached with repo in it)
              // worst case, 2+ API calls to gather user repos (1 call per 100 for batch load, 1 add'l call if public repo not in list)
              return authenticationToken.hasRepositoryPermission(repositoryName, permission);
            }

            // no match.
            return false;
        } else {
            String authenticatedUserName = a.getName();
            if (authenticatedUserName == null) {
                throw new IllegalArgumentException("Authentication must have a valid name");
            }

            if (authenticatedUserName.equals(SYSTEM.getPrincipal())) {
                // give system user full access
                log.finest("Granting Full rights to SYSTEM user.");
                return true;
            }

            if (authenticatedUserName.equals("anonymous")) {
                if (checkJobStatusPermission(permission) && allowAnonymousJobStatusPermission) {
                    return true;
                }

                if (checkReadPermission(permission)) {
                    if (allowAnonymousReadPermission) {
                        return true;
                    }
                    if (allowGithubWebHookPermission &&
                            (currentUriPathEquals("github-webhook") ||
                             currentUriPathEquals("github-webhook/"))) {
                        log.finest("Granting READ access for github-webhook url: " + requestURI());
                        return true;
                    }
                    if (allowCcTrayPermission && currentUriPathEndsWithSegment("cc.xml")) {
                        log.finest("Granting READ access for cctray url: " + requestURI());
                        return true;
                    }
                    log.finer("Denying anonymous READ permission to url: " + requestURI());
                }
                return false;
            }

            if (adminUserNameList.contains(authenticatedUserName)) {
                // if they are an admin then they have all permissions
                log.finest("Granting Admin rights to user " + a.getName());
                return true;
            }

            // else:
            // deny request
            //
            return false;
        }
    }

    @Nonnull
    private boolean isInWhitelistedOrgs(@Nonnull GithubAuthenticationToken authenticationToken) {
      return authenticationToken.isMemberOfAnyOrganizationInList(this.organizationNameList);
    }

    private boolean currentUriPathEquals( String specificPath ) {
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        String rootUrl = jenkins.getRootUrl();
        if (rootUrl == null) {
            throw new IllegalStateException("Could not determine Jenkins URL");
        }
        String requestUri = requestURI();
        if (requestUri != null) {
            String basePath = URI.create(rootUrl).getPath();
            return URI.create(requestUri).getPath().equals(basePath + specificPath);
        } else {
            return false;
        }
    }

    private boolean currentUriPathEndsWithSegment( String segment ) {
        String requestUri = requestURI();
        if (requestUri != null) {
          return requestUri.substring(requestUri.lastIndexOf('/') + 1).equals(segment);
        } else {
            return false;
        }
    }

    @Nullable
    private String requestURI() {
        StaplerRequest currentRequest = Stapler.getCurrentRequest();
        return (currentRequest == null) ? null : currentRequest.getOriginalRequestURI();
    }

    private boolean testBuildPermission(@Nonnull Permission permission) {
        String id = permission.getId();
        return id.equals("hudson.model.Hudson.Build")
                || id.equals("hudson.model.Item.Build");
    }

    private boolean checkReadPermission(@Nonnull Permission permission) {
        String id = permission.getId();
        return (id.equals("hudson.model.Hudson.Read")
                || id.equals("hudson.model.Item.Workspace")
                || id.equals("hudson.model.Item.Discover")
                || id.equals("hudson.model.Item.Read"));
    }

    private boolean checkJobStatusPermission(@Nonnull Permission permission) {
        return permission.getId().equals("hudson.model.Item.ViewStatus");
    }

    @Nullable
    private String getRepositoryName() {
        String repositoryName = null;
        String repoUrl = null;
        Describable scm = null;

        if (this.item instanceof WorkflowJob) {
            WorkflowJob job = (WorkflowJob) item;

            if(job.getProperty(BranchJobProperty.class) != null) {
                scm = job.getProperty(BranchJobProperty.class).getBranch().getScm();
            } else if (! job.getSCMs().isEmpty()) {
                scm = job.getSCMs().iterator().next();
            }
        } else if (this.item instanceof MultiBranchProject) {
            MultiBranchProject project = (MultiBranchProject) item;
            scm = (SCMSource) project.getSCMSources().get(0);
        } else if (this.item instanceof AbstractProject) {
            AbstractProject project = (AbstractProject) item;
            scm = project.getScm();
        }
        if (scm instanceof GitHubSCMSource) {
            GitHubSCMSource git = (GitHubSCMSource) scm;
            repoUrl = git.getRemote();
        } else if (scm instanceof GitSCM) {
            GitSCM git = (GitSCM) scm;
            List<UserRemoteConfig> userRemoteConfigs = git.getUserRemoteConfigs();
            if (!userRemoteConfigs.isEmpty()) {
                repoUrl = userRemoteConfigs.get(0).getUrl();
            }
        }
        if (repoUrl != null) {
            GitHubRepositoryName githubRepositoryName =
                GitHubRepositoryName.create(repoUrl);
            if (githubRepositoryName != null) {
                repositoryName = githubRepositoryName.userName + "/"
                    + githubRepositoryName.repositoryName;
            }
        }
        return repositoryName;
    }

    public GithubRequireOrganizationMembershipACL(String adminUserNames,
            String organizationNames,
            boolean authenticatedUserReadPermission,
            boolean useRepositoryPermissions,
            boolean authenticatedUserCreateJobPermission,
            boolean allowGithubWebHookPermission,
            boolean allowCcTrayPermission,
            boolean allowAnonymousReadPermission,
            boolean allowAnonymousJobStatusPermission) {
        super();

        this.authenticatedUserReadPermission      = authenticatedUserReadPermission;
        this.useRepositoryPermissions             = useRepositoryPermissions;
        this.authenticatedUserCreateJobPermission = authenticatedUserCreateJobPermission;
        this.allowGithubWebHookPermission         = allowGithubWebHookPermission;
        this.allowCcTrayPermission                = allowCcTrayPermission;
        this.allowAnonymousReadPermission         = allowAnonymousReadPermission;
        this.allowAnonymousJobStatusPermission    = allowAnonymousJobStatusPermission;
        this.adminUserNameList                    = new LinkedList<String>();

        String[] parts = adminUserNames.split(",");

        for (String part : parts) {
            adminUserNameList.add(part.trim());
        }

        this.organizationNameList = new LinkedList<String>();

        parts = organizationNames.split(",");

        for (String part : parts) {
            organizationNameList.add(part.trim());
        }

        this.item = null;
    }

    public GithubRequireOrganizationMembershipACL cloneForProject(AbstractItem item) {
      return new GithubRequireOrganizationMembershipACL(
          this.adminUserNameList,
          this.organizationNameList,
          this.authenticatedUserReadPermission,
          this.useRepositoryPermissions,
          this.authenticatedUserCreateJobPermission,
          this.allowGithubWebHookPermission,
          this.allowCcTrayPermission,
          this.allowAnonymousReadPermission,
          this.allowAnonymousJobStatusPermission,
          item);
    }

    public GithubRequireOrganizationMembershipACL(List<String> adminUserNameList,
            List<String> organizationNameList,
            boolean authenticatedUserReadPermission,
            boolean useRepositoryPermissions,
            boolean authenticatedUserCreateJobPermission,
            boolean allowGithubWebHookPermission,
            boolean allowCcTrayPermission,
            boolean allowAnonymousReadPermission,
            boolean allowAnonymousJobStatusPermission,
            AbstractItem item) {
        super();

        this.adminUserNameList                    = adminUserNameList;
        this.organizationNameList                 = organizationNameList;
        this.authenticatedUserReadPermission      = authenticatedUserReadPermission;
        this.useRepositoryPermissions             = useRepositoryPermissions;
        this.authenticatedUserCreateJobPermission = authenticatedUserCreateJobPermission;
        this.allowGithubWebHookPermission         = allowGithubWebHookPermission;
        this.allowCcTrayPermission                = allowCcTrayPermission;
        this.allowAnonymousReadPermission         = allowAnonymousReadPermission;
        this.allowAnonymousJobStatusPermission    = allowAnonymousJobStatusPermission;
        this.item = item;
    }

    public List<String> getOrganizationNameList() {
        return organizationNameList;
    }

    public List<String> getAdminUserNameList() {
        return adminUserNameList;
    }

    public boolean isUseRepositoryPermissions() {
        return useRepositoryPermissions;
    }

    public boolean isAuthenticatedUserCreateJobPermission() {
        return authenticatedUserCreateJobPermission;
    }

    public boolean isAuthenticatedUserReadPermission() {
        return authenticatedUserReadPermission;
    }

    public boolean isAllowGithubWebHookPermission() {
        return allowGithubWebHookPermission;
    }

    public boolean isAllowCcTrayPermission() {
        return allowCcTrayPermission;
    }

    /**
     * @return the allowAnonymousReadPermission
     */
    public boolean isAllowAnonymousReadPermission() {
        return allowAnonymousReadPermission;
    }

    public boolean isAllowAnonymousJobStatusPermission() {
        return allowAnonymousJobStatusPermission;
    }
}
