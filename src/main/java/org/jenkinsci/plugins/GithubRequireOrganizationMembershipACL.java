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

import hudson.security.ACL;
import hudson.security.Permission;

import java.io.File;
import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.kohsuke.stapler.Stapler;

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
	private final boolean allowGithubWebHookPermission;
    private final boolean allowCcTrayPermission;
    private final boolean allowEmbeddableBuildStatusIconPermission;
    private final boolean allowAnonymousReadPermission;

	/*
	 * (non-Javadoc)
	 * 
	 * @see hudson.security.ACL#hasPermission(org.acegisecurity.Authentication,
	 * hudson.security.Permission)
	 */
	@Override
	public boolean hasPermission(Authentication a, Permission permission) {

		if (a != null && a instanceof GithubAuthenticationToken) {

			if (!a.isAuthenticated())
				return false;

			GithubAuthenticationToken authenticationToken = (GithubAuthenticationToken) a;

			String candidateName = a.getName();

			if (adminUserNameList.contains(candidateName)) {
				// if they are an admin then they have permission
				log.finest("Granting Admin rights to user " + candidateName);
				return true;
			}

			if (authenticatedUserReadPermission) {

				if (checkReadPermission(permission)) {

					// if we support authenticated read and this is a read
					// request we allow it
					log.finest("Granting Authenticated User read permission to user "
							+ candidateName);
				return true;
				}
			}

			for (String organizationName : this.organizationNameList) {

				if (authenticationToken.hasOrganizationPermission(
						candidateName, organizationName)) {

					String[] parts = permission.getId().split("\\.");

					String test = parts[parts.length - 1].toLowerCase();

					if (checkReadPermission(permission)
							|| testBuildPermission(permission)) {
						// check the permission

						log.finest("Granting READ and BUILD rights to user "
								+ candidateName + " a member of "
								+ organizationName);
						return true;
					}
				}

			}

			// no match.
			return false;

		} else {

			String authenticatedUserName = a.getName();

			if (authenticatedUserName.equals(SYSTEM.getPrincipal())) {
				// give system user full access
				log.finest("Granting Full rights to SYSTEM user.");
				return true;
			}

			if (authenticatedUserName.equals("anonymous")) {

				if (allowAnonymousReadPermission
						&& checkReadPermission(permission)) {
					// grant anonymous read permission if that is desired to
					// anonymous users
					return true;
				}

                if (allowGithubWebHookPermission &&
                        (currentUriPathEquals( "github-webhook" ) ||
                         currentUriPathEquals( "github-webhook/" ))) {


					// allow if the permission was configured.

					if (checkReadPermission(permission)) {
						log.info("Granting READ access for github-webhook url: "
								+ requestURI());
						return true;
					}

					// else fall through to false.
				}

				if (allowCcTrayPermission && currentUriPathEquals("cc.xml")) {

					// allow if the permission was configured.

					if (checkReadPermission(permission)) {
						log.info("Granting READ access for cctray url: "
								+ requestURI());
						return true;
					}

					// else fall through to false.
				}

                if (allowEmbeddableBuildStatusIconPermission && currentUriIsEmbeddableBuildStatusIcon()) {
                    // allow if the permission was configured
                    if (checkReadPermission(permission)) {
                        log.info("Granting READ access for embeddable build status icon: "
                                + requestURI());
                        return true;
                    }

                    // else false through to false
                }

				log.finer("Denying anonymous READ permission to url: "
						+ requestURI());
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

    private boolean currentUriPathEquals( String specificPath ) {
        String basePath = URI.create(Jenkins.getInstance().getRootUrl()).getPath();
        return URI.create(requestURI()).getPath().equals(basePath + specificPath);
    }

    private boolean currentUriIsEmbeddableBuildStatusIcon() {
        /**
         * getJobNames() seems to result in an endless loop...
         *
        // iterate over job names and try to match against the request URI
        for (String jobName: Jenkins.getInstance().getJobNames()) {
            String testPath = basePath + "/job/" + jobName + "/badge/icon";

            if (requestPath.equals(testPath)) {
                hasMatch = true;
            }
        }
         */

        // while iterating over the jobNames is more ideal, getJobNames() results
        // in an endless loop, crashing Jenkins. As a workaround we are going to
        // check the validity of the request by checking for:
        // A. - the request was made to /.../job/.../badge/icon
        //      example: /jenkins/job/ci-uploadr/badge/icon
        //    - the path of this job exists on disk
        //
        // OR
        //
        // B. it is a request for a static resource (/.../static/...)
        //    example: /jenkins/static/b43fedd5/plugin/embeddable-build-status/status/success.png
        String requestPath  = URI.create(requestURI()).getPath();
        String jobName      = requestPath
                .replace("/badge/icon", "")
                .replaceAll(".*/","");
        String jobPath      = Jenkins.getInstance().getRootDir().getPath() + "/jobs/" + jobName;
        String baseURI      = Jenkins.getInstance()
                .getRootUrlFromRequest()
                .replace("http://", "")
                .replaceFirst("[^/]+/", "")
                .replaceAll("/$", "");
        Boolean isStaticRequest = (requestPath.startsWith("/" + baseURI + "/static/") &&
                requestPath.contains("/plugin/embeddable-build-status/"));
        Boolean isEmbeddableBadgeIcon = requestPath.equals("/" + baseURI + "/job/" + jobName + "/badge/icon");
        Boolean jobPathExists   = new File(jobPath).exists();

        // valid or not?
        return ((isEmbeddableBadgeIcon && jobPathExists) || isStaticRequest);
    }

    private String requestURI() {
        return Stapler.getCurrentRequest().getOriginalRequestURI();
    }

    private boolean testBuildPermission(Permission permission) {
		if (permission.getId().equals("hudson.model.Hudson.Build")
				|| permission.getId().equals("hudson.model.Item.Build")) {
			return true;
		} else
			return false;
	}

	private boolean checkReadPermission(Permission permission) {
		if (permission.getId().equals("hudson.model.Hudson.Read")
				|| permission.getId().equals("hudson.model.Item.Read")) {
			return true;
		} else
			return false;
	}

	public GithubRequireOrganizationMembershipACL(String adminUserNames,
			String organizationNames, boolean authenticatedUserReadPermission,
			boolean allowGithubWebHookPermission,
            boolean allowCcTrayPermission,
            boolean allowEmbeddableBuildStatusIconPermission,
			boolean allowAnonymousReadPermission) {
		super();
		this.authenticatedUserReadPermission = authenticatedUserReadPermission;
		this.allowGithubWebHookPermission = allowGithubWebHookPermission;
        this.allowCcTrayPermission = allowCcTrayPermission;
        this.allowEmbeddableBuildStatusIconPermission = allowEmbeddableBuildStatusIconPermission;
        this.allowAnonymousReadPermission = allowAnonymousReadPermission;

		this.adminUserNameList = new LinkedList<String>();

		String[] parts = adminUserNames.split(",");

		for (String part : parts) {
			adminUserNameList.add(part.trim());
		}

		this.organizationNameList = new LinkedList<String>();

		parts = organizationNames.split(",");

		for (String part : parts) {
			organizationNameList.add(part.trim());
		}

	}

	public List<String> getOrganizationNameList() {
		return organizationNameList;
	}

	public List<String> getAdminUserNameList() {
		return adminUserNameList;
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

    public boolean isAllowEmbeddableBuildStatusIconPermission() {
        return allowEmbeddableBuildStatusIconPermission;
    }

    /**
	 * @return the allowAnonymousReadPermission
	 */
	public boolean isAllowAnonymousReadPermission() {
		return allowAnonymousReadPermission;
	}

}
