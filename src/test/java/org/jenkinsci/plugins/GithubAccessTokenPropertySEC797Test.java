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

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.model.UnprotectedRootAction;
import hudson.util.HttpResponses;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.eclipse.jetty.util.Fields;
import org.eclipse.jetty.util.UrlEncoded;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest2;

//TODO merge with GithubAccessTokenPropertyTest after security release, just meant to ease the security merge
// or with GithubSecurityRealmTest, but will require more refactor to move out the mock server
public class GithubAccessTokenPropertySEC797Test {
    
    @Rule
    public JenkinsRule j = new JenkinsRule();
    
    private JenkinsRule.WebClient wc;
    
    private HttpServer server;
    private URI serverUri;
    private MockGithubServlet servlet;
    
    public void setupMockGithubServer() throws Exception {
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
        private List<String> teams;
        
        private JenkinsRule jenkinsRule;
        private URI serverUri;
        
        public MockGithubServlet(JenkinsRule jenkinsRule) {
            this.jenkinsRule = jenkinsRule;
        }
        
        public void setServerUrl(URI serverUri) {
            this.serverUri = serverUri;
        }
        
        @Override public void handle(HttpExchange he) throws IOException {
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
                responseBody.add(new HashMap<String, Object>() {{
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
            
            sendResponse(he, JSONArray.fromObject(responseBody).toString());
        }
        
        private void onUserTeams(HttpExchange he) throws IOException {
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
    
    @Before
    public void prepareRealmAndWebClient() throws Exception {
        this.setupMockGithubServer();
        this.setupRealm();
        wc = j.createWebClient();
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
    
    @After
    public void stopEmbeddedServer() {
        server.stop(1);
    }
    
    // all the code above is reused from GithubAccessTokenPropertyTest
    
    @Issue("SECURITY-797")
    @Test
    public void preventSessionFixation() throws Exception {
        TestRootAction rootAction = j.jenkins.getExtensionList(UnprotectedRootAction.class).get(TestRootAction.class);
        assertNotNull(rootAction);

        wc = j.createWebClient();

        String aliceLogin = "alice";
        servlet.currentLogin = aliceLogin;
        servlet.organizations = Collections.singletonList("org-a");
        servlet.teams = Collections.singletonList("team-b");
        
        String sessionIdBefore = checkSessionFixationWithOAuth();
        String sessionIdAfter = rootAction.sessionId;
        assertNotNull(sessionIdAfter);
        assertNotEquals("Session must be invalidated after login", sessionIdBefore, sessionIdAfter);
    }
    
    @TestExtension("preventSessionFixation")
    public static final class TestRootAction implements UnprotectedRootAction {
        public String sessionId;
        
        @Override
        public @CheckForNull String getIconFileName() {
            return null;
        }
        
        @Override
        public @CheckForNull String getDisplayName() {
            return null;
        }
        
        @Override
        public String getUrlName() {
            return "test";
        }
        
        public HttpResponse doIndex(StaplerRequest2 request) {
            HttpSession session = request.getSession(false);
            if (session == null) {
                sessionId = null;
            } else {
                sessionId = session.getId();
            }
            return HttpResponses.text("ok");
        }
    }
    
    private String checkSessionFixationWithOAuth() throws IOException {
        WebRequest req = new WebRequest(new URL(j.getURL(), "securityRealm/commenceLogin"));
        req.setEncodingType(null);
        
        String referer = j.getURL() + "test";
        req.setAdditionalHeader("Referer", referer);
        wc.getOptions().setRedirectEnabled(false);
        wc.getOptions().setThrowExceptionOnFailingStatusCode(false);
        Page p = wc.getPage(req);
        
        String cookie = p.getWebResponse().getResponseHeaderValue("Set-Cookie");
        String sessionId = StringUtils.substringBetween(cookie, "JSESSIONID=", ";");
        
        wc.getOptions().setRedirectEnabled(true);
        // continue the process of authentication
        wc.getPage(new URL(p.getWebResponse().getResponseHeaderValue("Location")));
        return sessionId;
    }
}
