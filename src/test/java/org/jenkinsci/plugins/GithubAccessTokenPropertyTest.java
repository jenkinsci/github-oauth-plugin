/*
 * The MIT License
 *
 * Copyright (c) 2017, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebRequest;
import hudson.model.User;
import hudson.util.Scrambler;
import jenkins.security.ApiTokenProperty;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.xml.sax.SAXException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class GithubAccessTokenPropertyTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private JenkinsRule.WebClient wc;

    private Server server;
    private URI serverUri;
    private MockGithubServlet servlet;

    public void setupMockGithubServer() throws Exception {
        server = new Server();
        ServerConnector connector = new ServerConnector(server);
        // auto-bind to available port
        connector.setPort(0);
        server.addConnector(connector);

        servlet = new MockGithubServlet(j);

        ServletContextHandler context = new ServletContextHandler();
        ServletHolder servletHolder = new ServletHolder("default", servlet);
        context.addServlet(servletHolder, "/*");
        server.setHandler(context);

        server.start();

        String host = connector.getHost();
        if (host == null) {
            host = "localhost";
        }

        int port = connector.getLocalPort();
        serverUri = new URI(String.format("http://%s:%d/", host, port));
        servlet.setServerUrl(serverUri);
    }

    /**
     * Based on documentation found at
     * https://developer.github.com/v3/users/
     * https://developer.github.com/v3/orgs/
     * https://developer.github.com/v3/orgs/teams/
     */
    private static class MockGithubServlet extends DefaultServlet {
        private String currentLogin;
        private List<String> organizations;
        private List<String> teams;

        private JenkinsRule jenkinsRule;
        private URI serverUri;

        public MockGithubServlet(JenkinsRule jenkinsRule) {
            this.jenkinsRule = jenkinsRule;
        }

        public void setServerUrl(URI serverUri) {
            this.serverUri = serverUri;
        }

        @Override protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            switch (req.getRequestURI()) {
                case "/user":
                    this.onUser(req, resp);
                    break;
                case "/users/_specific_login_":
                    this.onUser(req, resp);
                    break;
                case "/user/orgs":
                    this.onUserOrgs(req, resp);
                    break;
                case "/user/teams":
                    this.onUserTeams(req, resp);
                    break;
                case "/orgs/org-a":
                    this.onOrgs(req, resp, "org-a");
                    break;
                case "/orgs/org-a/teams":
                    this.onOrgsTeam(req, resp, "org-a");
                    break;
                case "/orgs/org-a/members/alice":
                    this.onOrgsMember(req, resp, "org-a", "alice");
                    break;
                case "/teams/7/members/alice":
                    this.onTeamMember(req, resp, "team-b", "alice");
                    break;
                case "/orgs/org-c":
                    this.onOrgs(req, resp, "org-c");
                    break;
                case "/orgs/org-c/teams":
                    this.onOrgsTeam(req, resp, "org-c");
                    break;
                case "/orgs/org-c/members/bob":
                    this.onOrgsMember(req, resp, "org-c", "bob");
                    break;
                case "/teams/7/members/bob":
                    this.onTeamMember(req, resp, "team-d", "bob");
                    break;
                case "/login/oauth/authorize":
                    this.onLoginOAuthAuthorize(req, resp);
                    break;
                case "/login/oauth/access_token":
                    this.onLoginOAuthAccessToken(req, resp);
                    break;
                default:
                    throw new RuntimeException("Url not mapped yet: " + req.getRequestURI());
            }
        }

        private void onUser(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            resp.getWriter().write(JSONObject.fromObject(
                    new HashMap<String, Object>() {{
                        put("login", currentLogin);
                        put("name", currentLogin + "_name");
                        // to avoid triggering a second call, due to GithubSecurityRealm:382
                        put("created_at", "2008-01-14T04:33:35Z");
                        put("url", serverUri + "/users/_specific_login_");
                    }}
            ).toString());
        }

        private void onUserOrgs(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            List<Map<String, Object>> responseBody = new ArrayList<>();
            for (String orgName : organizations) {
                final String orgName_ = orgName;
                responseBody.add(new HashMap<String, Object>() {{
                    put("login", orgName_);
                }});
            }

            resp.getWriter().write(JSONArray.fromObject(responseBody).toString());
        }

        private void onOrgs(HttpServletRequest req, HttpServletResponse resp, final String orgName) throws IOException {
            Map<String, Object> responseBody = new HashMap<String, Object>() {{
                put("login", orgName);
            }};

            resp.getWriter().write(JSONObject.fromObject(responseBody).toString());
        }

        private void onOrgsMember(HttpServletRequest req, HttpServletResponse resp, String orgName, String userName) throws IOException {
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            // 302 / 404 responses not implemented
        }

        private void onTeamMember(HttpServletRequest req, HttpServletResponse resp, String orgName, String userName) throws IOException {
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            // 302 / 404 responses not implemented
        }

        private void onOrgsTeam(HttpServletRequest req, HttpServletResponse resp, final String orgName) throws IOException {
            List<Map<String, Object>> responseBody = new ArrayList<>();
            for (String teamName : teams) {
                final String teamName_ = teamName;
                responseBody.add(new HashMap<String, Object>() {{
                    put("id", 7);
                    put("login", teamName_ + "_login");
                    put("name", teamName_);
                    put("organization", new HashMap<String, Object>() {{
                        put("login", orgName);
                    }});
                }});
            }

            resp.getWriter().write(JSONArray.fromObject(responseBody).toString());
        }

        private void onUserTeams(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            List<Map<String, Object>> responseBody = new ArrayList<>();
            for (String teamName : teams) {
                final String teamName_ = teamName;
                responseBody.add(new HashMap<String, Object>() {{
                    put("login", teamName_ + "_login");
                    put("name", teamName_);
                    put("organization", new HashMap<String, Object>() {{
                        put("login", organizations.get(0));
                    }});
                }});
            }

            resp.getWriter().write(JSONArray.fromObject(responseBody).toString());
        }

        private void onLoginOAuthAuthorize(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            String code = "test";
            String state = req.getParameter("state");
            resp.sendRedirect(jenkinsRule.getURL() + "securityRealm/finishLogin?code=" + code + "&state=" + state);
        }

        private void onLoginOAuthAccessToken(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            resp.getWriter().write("access_token=RANDOM_ACCESS_TOKEN");
        }
    }

    @Before
    public void prepareRealmAndWebClient() throws Exception {
        this.setupMockGithubServer();
        this.setupRealm();
        wc = j.createWebClient();
    }

    private void setupRealm(){
        String githubWebUri = serverUri.toString();
        String githubApiUri = serverUri.toString();
        String clientID = "xxx";
        String clientSecret = "yyy";
        String oauthScopes = "read:org";
        String authorizedOrgs = "";

        GithubSecurityRealm githubSecurityRealm = new GithubSecurityRealm(
                githubWebUri,
                githubApiUri,
                clientID,
                clientSecret,
                oauthScopes,
                authorizedOrgs
        );

        j.jenkins.setSecurityRealm(githubSecurityRealm);
    }

    @After
    public void stopEmbeddedJettyServer() {
        try {
            server.stop();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Issue("JENKINS-47113")
    @Test
    public void testUsingGithubToken() throws IOException, SAXException {
        String aliceLogin = "alice";
        servlet.currentLogin = aliceLogin;
        servlet.organizations = Arrays.asList("org-a");
        servlet.teams = Arrays.asList("team-b");

        User aliceUser = User.getById(aliceLogin, true);
        String aliceApiRestToken = aliceUser.getProperty(ApiTokenProperty.class).getApiToken();
        String aliceGitHubToken = "SPECIFIC_TOKEN";

        // request whoAmI with ApiRestToken => group not populated
        makeRequestWithAuthCodeAndVerify(encodeBasic(aliceLogin, aliceApiRestToken), "alice", Arrays.asList("authenticated"));

        // request whoAmI with GitHubToken => group populated
        makeRequestWithAuthCodeAndVerify(encodeBasic(aliceLogin, aliceGitHubToken), "alice", Arrays.asList("authenticated", "org-a", "org-a*team-b"));

        GithubAuthenticationToken.clearCaches();

        // no authentication in session but use the cache
        makeRequestWithAuthCodeAndVerify(encodeBasic(aliceLogin, aliceApiRestToken), "alice", Arrays.asList("authenticated", "org-a", "org-a*team-b"));

        wc = j.createWebClient();
        // no session at all, use the cache also
        makeRequestWithAuthCodeAndVerify(encodeBasic(aliceLogin, aliceApiRestToken), "alice", Arrays.asList("authenticated", "org-a", "org-a*team-b"));
    }

    @Issue("JENKINS-47113")
    @Test
    public void testUsingGithubLogin() throws IOException, SAXException {
        String bobLogin = "bob";
        servlet.currentLogin = bobLogin;
        servlet.organizations = Arrays.asList("org-c");
        servlet.teams = Arrays.asList("team-d");

        User bobUser = User.getById(bobLogin, true);
        String bobApiRestToken = bobUser.getProperty(ApiTokenProperty.class).getApiToken();

        // request whoAmI with ApiRestToken => group not populated
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated"));
        // request whoAmI with GitHub OAuth => group populated
        makeRequestUsingOAuth("bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));

        // use only the session
        // request whoAmI with ApiRestToken => group populated (due to login event)
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));

        GithubAuthenticationToken.clearCaches();
        wc = j.createWebClient();
        // retrieve the security group even without the cookie (using LastGrantedAuthorities this time)
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));
    }

    private void makeRequestWithAuthCodeAndVerify(String authCode, String expectedLogin, List<String> expectedAuthorities) throws IOException, SAXException {
        WebRequest req = new WebRequest(new URL(j.getURL(), "whoAmI/api/json"));
        req.setEncodingType(null);
        if (authCode != null)
            req.setAdditionalHeader("Authorization", authCode);
        Page p = wc.getPage(req);

        assertResponse(p, expectedLogin, expectedAuthorities);
    }

    private void makeRequestUsingOAuth(String expectedLogin, List<String> expectedAuthorities) throws IOException {
        WebRequest req = new WebRequest(new URL(j.getURL(), "securityRealm/commenceLogin"));
        req.setEncodingType(null);

        String referer = j.getURL() + "whoAmI/api/json";
        req.setAdditionalHeader("Referer", referer);
        Page p = wc.getPage(req);

        assertResponse(p, expectedLogin, expectedAuthorities);
    }

    private void assertResponse(Page p, String expectedLogin, List<String> expectedAuthorities) {
        String response = p.getWebResponse().getContentAsString().trim();
        JSONObject respObject = JSONObject.fromObject(response);
        if (expectedLogin != null) {
            assertEquals(expectedLogin, respObject.getString("name"));
        }
        if (expectedAuthorities != null) {
            // we use set to avoid having duplicated "authenticated"
            // as that will be corrected in https://github.com/jenkinsci/jenkins/pull/3123
            Set<String> actualAuthorities = new HashSet<>(
                    JSONArray.toCollection(
                            respObject.getJSONArray("authorities"),
                            String.class
                    )
            );

            Set<String> expectedAuthoritiesSet = new HashSet<>(expectedAuthorities);

            assertTrue(String.format("They do not have the same content, expected=%s, actual=%s", expectedAuthorities, actualAuthorities),
                    expectedAuthoritiesSet.equals(actualAuthorities));
        }
    }

    private String encodeBasic(String login, String credentials) {
        return "Basic " + Scrambler.scramble(login + ":" + credentials);
    }
}
