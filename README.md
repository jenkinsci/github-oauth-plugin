# Jenkins GitHub OAuth Plugin

* License: [MIT Licensed](LICENSE.txt)
* Read more: [GitHub OAuth Plugin wiki page][wiki]
* Latest build: [![Build Status][build-image]][build-link]
* [Contributions are welcome](CONTRIBUTING.md).

# Overview

The GitHub Authentication plugin provides a means of securing a Jenkins instance by
offloading authentication and authorization to GitHub.  The plugin authenticates
by using a [GitHub OAuth Application][github-wiki-oauth].  It can use multiple
authorization strategies for authorizing users.  GitHub users are surfaced as
Jenkins users for authorization.  GitHub organizations and teams are surfaced as
Jenkins groups for authorization.  This plugin supports GitHub Enterprise.

## Setup

Before configuring the plugin you must create a GitHub application
registration.

1.  Visit <https://github.com/settings/applications/new> to create a
    GitHub application registration.
2.  The values for application name, homepage URL, or application
    description don't matter. They can be customized however desired.
3.  However, the authorization callback URL takes a specific value. It
    must be `https://jenkins.example.com/securityRealm/finishLogin`
    where jenkins.example.com is the location of the Jenkins server.

    The important part of the callback URL is
    `/securityRealm/finishLogin`

4.  Finish by clicking *Register application*.

The *Client ID* and the *Client Secret* will be used to configure the
Jenkins Security Realm. Keep the page open to the application
registration so this information can be copied to your Jenkins
configuration.

#### Security Realm in Global Security

The security realm in Jenkins controls authentication (i.e. you are who
you say you are). The GitHub Authentication Plugin provides a security
realm to authenticate Jenkins users via GitHub OAuth.

1.  In the Global Security configuration choose the Security Realm to be
    **GitHub Authentication Plugin**.
2.  The settings to configure are: GitHub Web URI, GitHub API URI,
    Client ID, Client Secret, and OAuth Scope(s).
3.  If you're using GitHub Enterprise then the API URI is
    <https://ghe.example.com/api/v3>.

    The GitHub Enterprise API URI ends with `/api/v3`.

4.  The recommended minimum [GitHub OAuth
    scopes](https://developer.github.com/v3/oauth/#scopes) are
    `read:org,user:email`.

    The recommended scopes are designed for using both authentication
    and authorization functions in the plugin. If only authentication is
    being used then the scope can be further limited to `(no scope)` or
    `user:email`.

In the plugin configuration pages each field has a little
(❓) next to it. Click on it for help about the setting.

#### Authorization in Global Security.

The authorization configuration in Jenkins controls what your users can
do (i.e. read jobs, execute builds, administer permissions, etc.). The
GitHub OAuth Plugin supports multiple ways of configuring authorization.

It is highly recommended that you configure the security realm and log
in via GitHub OAuth before configuring authorization. This way Jenkins
can look up and verify users and groups if configuring matrix-based
authorization.

##### Github Committer Authorization Strategy

Control user authorization using the **Github Committer Authorization
Strategy**. This is the simplest authorization strategy to get up and
running. It handles authorization based on the git URL of a job and the
type of access a user has to that project (i.e. Admin, Read/Write,
Read-Only).

There is a way to authorize the use of the `/github-webhook` callback
url to receive post commit hooks from GitHub. This authorization
strategy has a checkbox that can allow GitHub POST data to be received.
You will still need to run the [GitHub
Plugin](https://wiki.jenkins-ci.org/display/JENKINS/GitHub+Plugin) to
have the message trigger the build.

##### Logged-in users can do anything

There are a few ways to configure the plugin so that everyone on your
team has `Overall/Administer` access.

1.  Choose **Logged-in users can do anything** authorization strategy.
2.  Choose one of the matrix-based authorization strategies. Set
    `authenticated` users to `Overall/Administer` permissions. Set
    `anonymous` users to have `Overall/Read` permissions and perhaps the
    `ViewStatus` permission.

##### Matrix-based Authorization strategy

Control user authorization using **Matrix-based security** or
**Project-based Matrix Authorization Strategy**. Project-based Matrix
Authorization Strategy allows one to configure authorization globally
per project and, when using Project-based Matrix Authorization Strategy
with the CloudBees folder plugin, per folder.

There are a few built-in authorizations to consider.

-   `anonymous` - is anyone who has not logged in. Recommended
    permissions are just `Job/Discover` and `Job/ViewStatus`.
-   `authenticated` - is anyone who has logged in. You can configure
    permissions for anybody who has logged into Jenkins. Recommended
    permissions are `Overall/Read` and `View/Read`.

    `anonymous` and `authenticated` usernames are case sensitive and
    must be lower case. This is a consideration when configuring
    authorizations via Groovy. Keep in mind that `anonymous` shows up as
    *Anonymous* in the Jenkins UI.

You can configure authorization based on GitHub users, organizations, or
teams.

-   `username` - give permissions to a specific GitHub username.
-   `organization` - give permissions to every user that belongs to a
    specific GitHub organization.
-   `organization*team` - give permissions to a specific GitHub team of
    a GitHub organization. Notice that organization and team are
    separated by an asterisk (`*`).

## Other usage

#### Calling Jenkins API using GitHub Personal Access Tokens

You can make Jenkins API calls by using a GitHub personal access token.
One can still call the Jenkins API by using Jenkins tokens or use the
Jenkins CLI with an SSH key for authentication. However, the GitHub
OAuth plugin provides another way to call the Jenkins API by allowing
the use of a GitHub Personal Access Token.

1.  Generate a [GitHub *Personal Access
    Token*](https://github.com/settings/tokens) and give it only
    `read:org` scope.
2.  Use a username and GitHub personal access token to authenticate with
    the Jenkins API.

Here's an example using curl to start a build using parameters (username
`samrocketman` and password using the personal access token).

``` syntaxhighlighter-pre
curl -X POST https://jenkins.example.com/job/_jervis_generator/build --user "samrocketman:myGitHubPersonalAccessToken" --data-urlencode json='{"parameter": [{"name":"project", "value":"samrocketman/jervis"}]}'
```

#### Automatically configure security realm via script console

Configuration management could be used to configure the security realm
via the [Jenkins Script
Console](https://wiki.jenkins.io/display/JENKINS/Jenkins+Script+Console).
Here's a sample configuring plugin version 0.22.

``` syntaxhighlighter-pre
import hudson.security.SecurityRealm
import org.jenkinsci.plugins.GithubSecurityRealm
String githubWebUri = 'https://github.com'
String githubApiUri = 'https://api.github.com'
String clientID = 'someid'
String clientSecret = 'somesecret'
String oauthScopes = 'read:org'
SecurityRealm github_realm = new GithubSecurityRealm(githubWebUri, githubApiUri, clientID, clientSecret, oauthScopes)
//check for equality, no need to modify the runtime if no settings changed
if(!github_realm.equals(Jenkins.instance.getSecurityRealm())) {
    Jenkins.instance.setSecurityRealm(github_realm)
    Jenkins.instance.save()
}
```

#### Automatically configure authorization strategy via script console

Configuration management could be used to configure the authorization
strategy via the [Jenkins Script
Console](https://wiki.jenkins.io/display/JENKINS/Jenkins+Script+Console).
Here's a sample configuring plugin version 0.22.

``` syntaxhighlighter-pre
import org.jenkinsci.plugins.GithubAuthorizationStrategy
import hudson.security.AuthorizationStrategy

//permissions are ordered similar to web UI
//Admin User Names
String adminUserNames = 'samrocketman'
//Participant in Organization
String organizationNames = ''
//Use Github repository permissions
boolean useRepositoryPermissions = true
//Grant READ permissions to all Authenticated Users
boolean authenticatedUserReadPermission = false
//Grant CREATE Job permissions to all Authenticated Users
boolean authenticatedUserCreateJobPermission = false
//Grant READ permissions for /github-webhook
boolean allowGithubWebHookPermission = false
//Grant READ permissions for /cc.xml
boolean allowCcTrayPermission = false
//Grant READ permissions for Anonymous Users
boolean allowAnonymousReadPermission = false
//Grant ViewStatus permissions for Anonymous Users
boolean allowAnonymousJobStatusPermission = false

AuthorizationStrategy github_authorization = new GithubAuthorizationStrategy(adminUserNames,
    authenticatedUserReadPermission,
    useRepositoryPermissions,
    authenticatedUserCreateJobPermission,
    organizationNames,
    allowGithubWebHookPermission,
    allowCcTrayPermission,
    allowAnonymousReadPermission,
    allowAnonymousJobStatusPermission)

//check for equality, no need to modify the runtime if no settings changed
if(!github_authorization.equals(Jenkins.instance.getAuthorizationStrategy())) {
    Jenkins.instance.setAuthorizationStrategy(github_authorization)
    Jenkins.instance.save()
}
```

## Troubleshooting Installation

After installing, the `<securityRealm>` class should have
been updated in your `/var/lib/jenkins/config.xml` file. The value of
`<clientID>` should agree with what you pasted into the admin UI. If it doesn't
or you still can't log in, reset to `<securityRealm
class="hudson.security.HudsonPrivateSecurityRealm">` and restart Jenkins from
the command-line.


[build-image]: https://ci.jenkins.io/buildStatus/icon?job=Plugins/github-oauth-plugin/master
[build-link]: https://ci.jenkins.io/job/Plugins/job/github-oauth-plugin/job/master/
[github-wiki-oauth]: https://developer.github.com/v3/oauth/
[wiki]: https://wiki.jenkins-ci.org/display/JENKINS/Github+OAuth+Plugin
