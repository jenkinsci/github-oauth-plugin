/**
 *
 */
package org.jenkinsci.plugins;

import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHTeam;

import hudson.security.GroupDetails;

/**
 * @author Mike
 *
 */
public class GithubOAuthGroupDetails extends GroupDetails {

    private final GHOrganization org;
    private final GHTeam team;
    static final String ORG_TEAM_SEPARATOR = "*";

    /**
    * Group based on organization name
    * @param org
    */
    public GithubOAuthGroupDetails(GHOrganization org) {
        super();
        this.org = org;
        this.team = null;
    }

    /**
    * Group based on team name
     * @param ghTeam
     */
    public GithubOAuthGroupDetails(GHTeam team) {
        super();
        this.org = team.getOrganization();
        this.team = team;
    }

    /* (non-Javadoc)
    * @see hudson.security.GroupDetails#getName()
    */
    @Override
    public String getName() {
        if (team != null)
            return org.getLogin() + ORG_TEAM_SEPARATOR + team.getName();
        if (org != null)
            return org.getLogin();
        return null;
    }



}
