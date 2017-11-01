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
import org.junit.AfterClass;
import org.junit.BeforeClass;
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
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class Jenkins47113 {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private static JenkinsRule staticJenkins;

    private JenkinsRule.WebClient wc;

    public Jenkins47113() {
        staticJenkins = j;
    }

    private static Server server;
    private static URI serverUri;
    private static MockGithubServlet servlet;

    @BeforeClass
    public static void setupMockGithubServer() throws Exception {
        server = new Server();
        ServerConnector connector = new ServerConnector(server);
        // auto-bind to available port
        connector.setPort(0);
        server.addConnector(connector);

        servlet = new MockGithubServlet();

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
                case "/login/oauth/authorize":
                    this.onLoginOAuthAuthorize(req, resp);
                    break;
                case "/login/oauth/access_token":
                    this.onLoginOAuthAccessToken(req, resp);
                    break;
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
            resp.sendRedirect(staticJenkins.getURL() + "securityRealm/finishLogin?code=" + code);
        }

        private void onLoginOAuthAccessToken(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            resp.getWriter().write("access_token=RANDOM_ACCESS_TOKEN");
        }
    }

    @AfterClass
    public static void stopJetty() {
        try {
            server.stop();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Issue("JENKINS-47113")
    @Test
    public void testGroupPopulation() throws Exception {
        String githubWebUri = serverUri.toString();
        String githubApiUri = serverUri.toString();
        String clientID = "xxx";
        String clientSecret = "yyy";
        String oauthScopes = "read:org";

        GithubSecurityRealm githubSecurityRealm = new GithubSecurityRealm(
                githubWebUri,
                githubApiUri,
                clientID,
                clientSecret,
                oauthScopes
        );
        j.jenkins.setSecurityRealm(githubSecurityRealm);

        wc = j.createWebClient();

        testAlice_usingGithubToken();
        testBob_usingGithubLogin();
    }

    private void testAlice_usingGithubToken() throws IOException, SAXException {
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

        // there is neither loggedIn event triggered nor session at that point
        makeRequestWithAuthCodeAndVerify(encodeBasic(aliceLogin, aliceApiRestToken), "alice", Arrays.asList("authenticated"));

//        // in case we trigger loggedIn event when we authenticate with GitHub token.
//        makeRequestWithAuthCodeAndVerify(encodeBasic(aliceLogin, aliceApiRestToken), "alice", Arrays.asList("authenticated", "authenticated", "org-a", "org-a*team-b"));
//
//        wc = j.createWebClient();
//        // in case of GithubToken there is no session so we retrieve the same result
//        makeRequestWithAuthCodeAndVerify(encodeBasic(aliceLogin, aliceApiRestToken), "alice", Arrays.asList("authenticated", "authenticated", "org-a", "org-a*team-b"));
    }

    private void testBob_usingGithubLogin() throws IOException, SAXException {
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

        wc = j.createWebClient();
        // retrieve the security group even without the cookie (using LastGrantedAuthorities this time)
        // twice the authenticated because one from the cache and one from the current request
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated", "authenticated", "org-c", "org-c*team-d"));
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
