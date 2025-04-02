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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import hudson.model.User;
import hudson.util.Scrambler;
import jenkins.security.ApiTokenProperty;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.eclipse.jetty.util.Fields;
import org.eclipse.jetty.util.UrlEncoded;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@WithJenkins
class GithubAccessTokenPropertyTest {

    private JenkinsRule j;

    private JenkinsRule.WebClient wc;

    private HttpServer server;
    private URI serverUri;
    private MockGithubServlet servlet;

    private void setupMockGithubServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        servlet = new MockGithubServlet(j);
        server.createContext("/", servlet);
        server.start();

        InetSocketAddress address = server.getAddress();
        serverUri = new URI(String.format("http://%s:%d/", address.getHostString(), address.getPort()));
        servlet.setServerUrl(serverUri);
    }

    /**
     * Based on documentation found at
     * https://developer.github.com/v3/users/
     * https://developer.github.com/v3/orgs/
     * https://developer.github.com/v3/orgs/teams/
     */
    private static class MockGithubServlet implements HttpHandler {
        private String currentLogin;
        private List<String> organizations;
        private List<Map<String, String>> teams;

        private final JenkinsRule jenkinsRule;
        private URI serverUri;

        public MockGithubServlet(JenkinsRule jenkinsRule) {
            this.jenkinsRule = jenkinsRule;
        }

        public void setServerUrl(URI serverUri) {
            this.serverUri = serverUri;
        }

        @Override
        public void handle(HttpExchange he) throws IOException {
            switch (he.getRequestURI().getPath()) {
                case "/user":
                    this.onUser(he);
                    break;
                case "/users/_specific_login_":
                    this.onUser(he);
                    break;
                case "/user/orgs":
                    this.onUserOrgs(he);
                    break;
                case "/user/teams":
                    this.onUserTeams(he);
                    break;
                case "/orgs/org-a":
                    this.onOrgs(he, "org-a");
                    break;
                case "/orgs/org-a/teams":
                    this.onOrgsTeam(he, "org-a");
                    break;
                case "/orgs/org-a/members/alice":
                    this.onOrgsMember(he, "org-a", "alice");
                    break;
                case "/teams/7/members/alice":
                    this.onTeamMember(he, "team-b", "alice");
                    break;
                case "/orgs/org-c":
                    this.onOrgs(he, "org-c");
                    break;
                case "/orgs/org-c/teams":
                    this.onOrgsTeam(he, "org-c");
                    break;
                case "/orgs/org-c/members/bob":
                    this.onOrgsMember(he, "org-c", "bob");
                    break;
                case "/teams/7/members/bob":
                    this.onTeamMember(he, "team-d", "bob");
                    break;
                case "/login/oauth/authorize":
                    this.onLoginOAuthAuthorize(he);
                    break;
                case "/login/oauth/access_token":
                    this.onLoginOAuthAccessToken(he);
                    break;
                default:
                    throw new RuntimeException("Url not mapped yet: " + he.getRequestURI().getPath());
            }
            he.close();
        }

        private void onUser(HttpExchange he) throws IOException {
            sendResponse(he, JSONObject.fromObject(
                    new HashMap<String, Object>() {{
                        put("login", currentLogin);
                        put("name", currentLogin + "_name");
                        // to avoid triggering a second call, due to GithubSecurityRealm:382
                        put("created_at", "2008-01-14T04:33:35Z");
                        put("url", serverUri + "/users/_specific_login_");
                    }}
            ).toString());
        }

        private void onUserOrgs(HttpExchange he) throws IOException {
            List<Map<String, Object>> responseBody = new ArrayList<>();
            for (String orgName : organizations) {
                final String orgName_ = orgName;
                responseBody.add(new HashMap<>() {{
                    put("login", orgName_);
                }});
            }
            sendResponse(he, JSONArray.fromObject(responseBody).toString());
        }

        private void onOrgs(HttpExchange he, final String orgName) throws IOException {
            Map<String, Object> responseBody = new HashMap<String, Object>() {{
                put("login", orgName);
            }};
            sendResponse(he, JSONObject.fromObject(responseBody).toString());
        }

        private void onOrgsMember(HttpExchange he, String orgName, String userName) throws IOException {
            he.sendResponseHeaders(HttpURLConnection.HTTP_NO_CONTENT, -1);
            // 302 / 404 responses not implemented
        }

        private void onTeamMember(HttpExchange he, String orgName, String userName) throws IOException {
            he.sendResponseHeaders(HttpURLConnection.HTTP_NO_CONTENT, -1);
            // 302 / 404 responses not implemented
        }

        private void onOrgsTeam(HttpExchange he, final String orgName) throws IOException {
            List<Map<String, Object>> responseBody = new ArrayList<>();
            for (Map<String, String> team : teams) {
                final String teamName_ = team.get("name");
                final String slug = team.get("slug");
                responseBody.add(new HashMap<>() {{
                    put("id", 7);
                    put("login", teamName_ + "_login");
                    put("name", teamName_);
                    put("slug", slug);
                    put("organization", new HashMap<String, Object>() {{
                        put("login", orgName);
                    }});
                }});
            }
            sendResponse(he, JSONArray.fromObject(responseBody).toString());
        }

        private void onUserTeams(HttpExchange he) throws IOException {
            List<Map<String, Object>> responseBody = new ArrayList<>();
            for (Map<String, String> team : teams) {
                final String teamName_ = team.get("name");
                final String slug = team.get("slug");
                responseBody.add(new HashMap<>() {{
                    put("login", teamName_ + "_login");
                    put("name", teamName_);
                    put("slug", slug);
                    put("organization", new HashMap<String, Object>() {{
                        put("login", organizations.get(0));
                    }});
                }});
            }

            sendResponse(he, JSONArray.fromObject(responseBody).toString());
        }

        private void onLoginOAuthAuthorize(HttpExchange he) throws IOException {
            String code = "test";
            Fields fields = new Fields();
            UrlEncoded.decodeUtf8To(he.getRequestURI().getQuery(), fields);
            String state = fields.getValue("state");
            he.getResponseHeaders().set("Location", jenkinsRule.getURL() + "securityRealm/finishLogin?code=" + code + "&state=" + state);
            he.sendResponseHeaders(302, -1);
        }

        private void onLoginOAuthAccessToken(HttpExchange he) throws IOException {
            sendResponse(he, "access_token=RANDOM_ACCESS_TOKEN");
        }

        private void sendResponse(HttpExchange he, String response) throws IOException {
            byte[] body = response.getBytes(StandardCharsets.UTF_8);
            he.sendResponseHeaders(HttpURLConnection.HTTP_OK, body.length);
            try (OutputStream os = he.getResponseBody()) {
                os.write(body);
            }
        }
    }

    @BeforeEach
    void prepareRealmAndWebClient(JenkinsRule j) throws Exception {
        this.j = j;
        this.setupMockGithubServer();
        this.setupRealm();
        wc = j.createWebClient();
        GithubAuthenticationToken.clearCaches();
    }

    private void setupRealm() {
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
    }

    @AfterEach
    void stopEmbeddedJettyServer() {
        server.stop(1);
    }

    @Issue("JENKINS-47113")
    @Test
    void testUsingGithubToken() throws IOException {
        String aliceLogin = "alice";
        servlet.currentLogin = aliceLogin;
        servlet.organizations = Collections.singletonList("org-a");
        Map<String, String> team = new HashMap<>();
        team.put("slug", "team-b");
        team.put("name", "Team D");
        servlet.teams = Collections.singletonList(team);

        User aliceUser = User.getById(aliceLogin, true);
        String aliceApiRestToken = aliceUser.getProperty(ApiTokenProperty.class).getApiToken();
        String aliceGitHubToken = "SPECIFIC_TOKEN";

        // request whoAmI with ApiRestToken => group populated
        makeRequestWithAuthCodeAndVerify(encodeBasic(aliceLogin, aliceApiRestToken), "alice", Arrays.asList("authenticated", "org-a", "org-a*team-b"));

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
    void testUsingGithubLogin() throws IOException {
        String bobLogin = "bob";
        servlet.currentLogin = bobLogin;
        servlet.organizations = Collections.singletonList("org-c");
        Map<String, String> team = new HashMap<>();
        team.put("slug", "team-d");
        team.put("name", "Team D");
        servlet.teams = Collections.singletonList(team);

        User bobUser = User.getById(bobLogin, true);
        String bobApiRestToken = bobUser.getProperty(ApiTokenProperty.class).getApiToken();

        // request whoAmI with ApiRestToken => group populated
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));
        // request whoAmI with GitHub OAuth => group populated
        makeRequestUsingOAuth("bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));

        // use only the session
        // request whoAmI with ApiRestToken => group populated (due to login event)
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));

        GithubAuthenticationToken.clearCaches();

        // retrieve the security group even without the cookie (using LastGrantedAuthorities this time)
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));
    }

    @Issue("JENKINS-60200")
    @Test
    void testInvalidateAuthorizationCacheOnFreshLogin() throws IOException {
        String bobLogin = "bob";
        servlet.currentLogin = bobLogin;
        servlet.organizations = Collections.singletonList("org-c");
        Map<String, String> team = new HashMap<>();
        team.put("slug", "team-d");
        team.put("name", "Team D");
        servlet.teams = Collections.singletonList(team);

        User bobUser = User.getById(bobLogin, true);
        String bobApiRestToken = bobUser.getProperty(ApiTokenProperty.class).getApiToken();

        // request whoAmI with ApiRestToken => group populated
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));
        // request whoAmI with GitHub OAuth => group populated
        makeRequestUsingOAuth("bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));

        // Switch the teams
        team.put("slug", "team-e");
        team.put("name", "Team E");
        servlet.teams = Collections.singletonList(team);

        // With just AuthCode, the cache is not invalidated
        makeRequestWithAuthCodeAndVerify(encodeBasic(bobLogin, bobApiRestToken), "bob", Arrays.asList("authenticated", "org-c", "org-c*team-d"));

        // With OAuth the cache is invalidated
        makeRequestUsingOAuth("bob", Arrays.asList("authenticated", "org-c", "org-c*team-e"));
    }

    private void makeRequestWithAuthCodeAndVerify(String authCode, String expectedLogin, List<String> expectedAuthorities) throws IOException {
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

    private static void assertResponse(Page p, String expectedLogin, List<String> expectedAuthorities) {
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

            assertEquals(expectedAuthoritiesSet, actualAuthorities, String.format("They do not have the same content, expected=%s, actual=%s", expectedAuthorities, actualAuthorities));
        }
    }

    private static String encodeBasic(String login, String credentials) {
        return "Basic " + Scrambler.scramble(login + ":" + credentials);
    }
}
