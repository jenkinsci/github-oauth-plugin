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

import com.google.common.collect.ImmutableList;
import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Job;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import java.util.Collection;

/**
 * @author mocleiri
 *
 *
 *
 */
public class GithubAuthorizationStrategy extends AuthorizationStrategy {

    @DataBoundConstructor
    public GithubAuthorizationStrategy(String adminUserNames,
            boolean authenticatedUserReadPermission,
            boolean useRepositoryPermissions,
            boolean authenticatedUserCreateJobPermission,
            String organizationNames,
            boolean allowGithubWebHookPermission,
            boolean allowCcTrayPermission,
            boolean allowAnonymousReadPermission,
            boolean allowAnonymousJobStatusPermission) {
        super();

        rootACL = new GithubRequireOrganizationMembershipACL(adminUserNames,
                organizationNames,
                authenticatedUserReadPermission,
                useRepositoryPermissions,
                authenticatedUserCreateJobPermission,
                allowGithubWebHookPermission,
                allowCcTrayPermission,
                allowAnonymousReadPermission,
                allowAnonymousJobStatusPermission);
    }

    private final GithubRequireOrganizationMembershipACL rootACL;

    /*
     * (non-Javadoc)
     * @return rootAcl
     * @see hudson.security.AuthorizationStrategy#getRootACL()
     */
    @Nonnull
    @Override
    public ACL getRootACL() {
        return rootACL;
    }

    @Nonnull
    public ACL getACL(@Nonnull Job<?,?> job) {
        if(job instanceof AbstractProject) {
            AbstractProject project = (AbstractProject)job;
            GithubRequireOrganizationMembershipACL githubACL = (GithubRequireOrganizationMembershipACL) getRootACL();
            return githubACL.cloneForProject(project);
        } else {
            return getRootACL();
        }
    }

    /**
     * (non-Javadoc)
     * @return groups
     * @see hudson.security.AuthorizationStrategy#getGroups()
     */
    @Nonnull
    @Override
    public Collection<String> getGroups() {
        return ImmutableList.of();
    }

    private Object readResolve() {
        return this;
    }

    /**
     * @return organizationNames
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#getOrganizationNameList()
     */
    public String getOrganizationNames() {
        return StringUtils.join(rootACL.getOrganizationNameList().iterator(), ", ");
    }

    /**
     * @return adminUserNames
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#getAdminUserNameList()
     */
    public String getAdminUserNames() {
        return StringUtils.join(rootACL.getAdminUserNameList().iterator(), ", ");
    }

    /**
     * @return isUseRepositoryPermissions
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isUseRepositoryPermissions()
     */
    public boolean isUseRepositoryPermissions() {
        return rootACL.isUseRepositoryPermissions();
    }

    /**
     * @return isAuthenticatedUserCreateJobPermission
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAuthenticatedUserCreateJobPermission()
     */
    public boolean isAuthenticatedUserCreateJobPermission() {
        return rootACL.isAuthenticatedUserCreateJobPermission();
    }

    /**
     * @return isAuthenticatedUserReadPermission
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAuthenticatedUserReadPermission()
     */
    public boolean isAuthenticatedUserReadPermission() {
        return rootACL.isAuthenticatedUserReadPermission();
    }

    /**
     * @return isAllowGithubWebHookPermission
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAllowGithubWebHookPermission()
     */
    public boolean isAllowGithubWebHookPermission() {
        return rootACL.isAllowGithubWebHookPermission();
    }

    /**
     * @return isAllowCcTrayPermission
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAllowCcTrayPermission()
     */
    public boolean isAllowCcTrayPermission() {
        return rootACL.isAllowCcTrayPermission();
    }


    /**
     * @return isAllowAnonymousReadPermission
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAllowAnonymousReadPermission()
     */
    public boolean isAllowAnonymousReadPermission() {
        return rootACL.isAllowAnonymousReadPermission();
    }

    /**
     * @return isAllowAnonymousJobStatusPermission
     * @see org.jenkinsci.plugins.GithubRequireOrganizationMembershipACL#isAllowAnonymousJobStatusPermission()
     */
    public boolean isAllowAnonymousJobStatusPermission() {
        return rootACL.isAllowAnonymousJobStatusPermission();
    }

    /**
     * Compare an object against this instance for equivalence.
     * @param object An object to campare this instance to.
     * @return true if the objects are the same instance and configuration.
     */
    @Override
    public boolean equals(Object object){
        if(object instanceof GithubAuthorizationStrategy) {
            GithubAuthorizationStrategy obj = (GithubAuthorizationStrategy) object;
            return this.getOrganizationNames().equals(obj.getOrganizationNames()) &&
                this.getAdminUserNames().equals(obj.getAdminUserNames()) &&
                this.isUseRepositoryPermissions() == obj.isUseRepositoryPermissions() &&
                this.isAuthenticatedUserCreateJobPermission() == obj.isAuthenticatedUserCreateJobPermission() &&
                this.isAuthenticatedUserReadPermission() == obj.isAuthenticatedUserReadPermission() &&
                this.isAllowGithubWebHookPermission() == obj.isAllowGithubWebHookPermission() &&
                this.isAllowCcTrayPermission() == obj.isAllowCcTrayPermission() &&
                this.isAllowAnonymousReadPermission() == obj.isAllowAnonymousReadPermission() &&
                this.isAllowAnonymousJobStatusPermission() == obj.isAllowAnonymousJobStatusPermission();
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return rootACL != null ? rootACL.hashCode() : 0;
    }

    @Extension
    public static final class DescriptorImpl extends
            Descriptor<AuthorizationStrategy> {

        public String getDisplayName() {
            return "GitHub Committer Authorization Strategy";
        }

        public String getHelpFile() {
            return "/plugin/github-oauth/help/help-authorization-strategy.html";
        }
    }
}
