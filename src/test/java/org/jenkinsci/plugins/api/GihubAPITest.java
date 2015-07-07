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
package org.jenkinsci.plugins.api;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.junit.Ignore;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHTeam;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;

/**
 * @author mocleiri
 *
 * we ignore this test when running the automated tests.
 */
@Ignore
public class GihubAPITest extends TestCase {

    /**
     *
     */
    public GihubAPITest() {
        // TODO Auto-generated constructor stub
    }

    private static final String LOGIN = System.getProperty("github.login");
    private static final String API_TOKEN = System.getProperty("github.api");

    // I would sugest with the repo level of permission.
    private static final String OAUTH_TOKEN = System.getProperty("github.oauth");

    // the name of the organization to which the login is a participant.
    private static final String PARTICPATING_ORG = System.getProperty("github.org");

    /**
     * @param name
     */
    public GihubAPITest(String name) {
        super(name);
        // TODO Auto-generated constructor stub
    }

    public void testWithUserAPIToken() throws IOException {
        GitHub gh = GitHub.connect(LOGIN, API_TOKEN);

        GHOrganization org = gh.getOrganization(PARTICPATING_ORG);

        Map<String, GHTeam> teams = org.getTeams();

        boolean found = false;

        for (GHTeam team : teams.values()) {
            System.out.println("team = " + team.getName() + ", permission = "
                    + team.getPermission());

            // check for membership
            for (GHUser member : team.getMembers()) {
                System.out.println("member = " + member.getLogin());

                if (member.getLogin().equals(LOGIN)) {
                    found = true;
                }
            }
        }

        assertTrue(found);
    }

    public void testOrganizationMembership () throws IOException {
        GitHub gh = GitHub.connectUsingOAuth(OAUTH_TOKEN);

        Map<String, GHOrganization> orgs = gh.getMyOrganizations();

        for (String orgName : orgs.keySet()) {
            GHOrganization org = orgs.get(orgName);

            Map<String, GHTeam> teams = org.getTeams();

            System.out.println("org = " + orgName);

            for (String name : teams.keySet()) {
                GHTeam team = teams.get(name);

                Set<GHUser> members = team.getMembers();

                System.out.println("team = " + team.getName());

                for (GHUser ghUser : members) {
                    System.out.println("member = " + ghUser.getLogin());
                }
            }
        }

        assertTrue(true);
    }

    public void testOrganizationMembershipAPI () throws IOException {
        GitHub gh = GitHub.connect(LOGIN, API_TOKEN);

        Map<String, GHOrganization> orgs = gh.getMyOrganizations();

        for (String orgName : orgs.keySet()) {
            GHOrganization org = orgs.get(orgName);

            System.out.println("org = " + orgName);
        }

        assertTrue(true);
    }

    // /organizations
    public void testWithOAuthToken() throws IOException {
        GitHub gh = GitHub.connectUsingOAuth(OAUTH_TOKEN);

        GHUser me = gh.getMyself();

        GHOrganization org = gh.getOrganization(PARTICPATING_ORG);

        Map<String, GHTeam> teams = org.getTeams();

        boolean found = false;

        for (GHTeam team : teams.values()) {
            System.out.println("team = " + team.getName() + ", permission = "
                    + team.getPermission());

            // check for membership
            for (GHUser member : team.getMembers()) {
                System.out.println("member = " + member.getLogin());

                if (member.getLogin().equals(LOGIN)) {
                    found = true;
                }
            }
        }

        assertTrue(found);
    }
}
