/**
 * 
 */
package org.jenkinsci.plugins;

import org.kohsuke.github.GHOrganization;

import hudson.security.GroupDetails;

/**
 * @author Mike
 *
 */
public class GithubOAuthGroupDetails extends GroupDetails {

	private final GHOrganization org;

	public GithubOAuthGroupDetails(GHOrganization org) {
		super();
		this.org = org;
	}

	/* (non-Javadoc)
	 * @see hudson.security.GroupDetails#getName()
	 */
	@Override
	public String getName() {
		if (org != null)
			return org.getLogin();
		else
			return null;
	}

	

}
