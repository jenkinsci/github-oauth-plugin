# Version 0.28.1 (Released Nov 2, 2017)

- Fix a botched release.  0.28 was not released to Artifactory so this is
  another attempt.

# Version 0.28 (Released Oct 1, 2017)

- Corrected a connectivity error on auth with proxy tracked by
  [JENKINS-45726][JENKINS-45726]. (pull request [#85][#85])

[#85]: https://github.com/jenkinsci/github-oauth-plugin/pull/85
[JENKINS-45726]: https://issues.jenkins-ci.org/browse/JENKINS-45726

# Version 0.27 (Released May 1, 2017)

- Allow collaborators to cancel/abort a build tracked by
  [JENKINS-40566][JENKINS-40566]. (pull request [#81][#81])
- Bugfix breaking SSH key authentication and transport authentication in Jenkins
  CLI tracked by [JENKINS-43822][JENKINS-43822]. (pull request [#83][#83])

[#81]: https://github.com/jenkinsci/github-oauth-plugin/pull/81
[#83]: https://github.com/jenkinsci/github-oauth-plugin/pull/83
[JENKINS-40566]: https://issues.jenkins-ci.org/browse/JENKINS-40566
[JENKINS-43822]: https://issues.jenkins-ci.org/browse/JENKINS-43822

# Version 0.26 (Released Apr 21, 2017)

- Bugfix Fix for NPE in `GithubOAuthUserDetails.getAuthorities()`. (pull request
  [#76][#76])
- Bugfix [JENKINS-27045][JENKINS-27045] Jenkins CLI --username/--password
  options. (pull request [#77][#77])
- Bugfix [JENKINS-38096][JENKINS-38096] add in authorization checks for
  multibranch workflow jobs. (pull request [#78][#78])

[#76]: https://github.com/jenkinsci/github-oauth-plugin/pull/76
[#77]: https://github.com/jenkinsci/github-oauth-plugin/pull/77
[#78]: https://github.com/jenkinsci/github-oauth-plugin/pull/78
[JENKINS-27045]: https://issues.jenkins-ci.org/browse/JENKINS-27045
[JENKINS-38096]: https://issues.jenkins-ci.org/browse/JENKINS-38096

# Version 0.25 (Released Dec 3, 2016)

- Security improvement: Added support for SSL server name indication. (pull
  request [#59][#59])
- Security improvement: release over HTTPS. (pull request [#67][#67])
- Performance enhancement: Fixes github client rate limitor waits and eats web
  threads causing Jenkins to be unresponsive tracked by
  [JENKINS-39200][JENKINS-39200].  (pull request [#63][#63])
- Performance enhancement: cache user lookups from GitHub. (pull requests
  [#64][#64], [#65][#65], [#71][#71], [#72][#72], [#73][#73])
- Bugfix skip searching users when searching for teams tracked by
  [JENKINS-34896][JENKINS-34896] (pull request [#68][#68])
- Bugfix logout/login process tracked by [JENKINS-16350][JENKINS-16350]. (pull
  request [#58][#58])
- Bugfix building plugin with JDK7 and JDK8. (pull request [#73][#73])
- General bug fixes and code cleanup. (pull requests [#61][#61], [#62][#62],
  [#66][#66], [#69][#69], [#70][#70])

[#58]: https://github.com/jenkinsci/github-oauth-plugin/pull/58
[#59]: https://github.com/jenkinsci/github-oauth-plugin/pull/59
[#61]: https://github.com/jenkinsci/github-oauth-plugin/pull/61
[#62]: https://github.com/jenkinsci/github-oauth-plugin/pull/62
[#63]: https://github.com/jenkinsci/github-oauth-plugin/pull/63
[#64]: https://github.com/jenkinsci/github-oauth-plugin/pull/64
[#65]: https://github.com/jenkinsci/github-oauth-plugin/pull/65
[#66]: https://github.com/jenkinsci/github-oauth-plugin/pull/66
[#67]: https://github.com/jenkinsci/github-oauth-plugin/pull/67
[#68]: https://github.com/jenkinsci/github-oauth-plugin/pull/68
[#69]: https://github.com/jenkinsci/github-oauth-plugin/pull/69
[#70]: https://github.com/jenkinsci/github-oauth-plugin/pull/70
[#71]: https://github.com/jenkinsci/github-oauth-plugin/pull/71
[#72]: https://github.com/jenkinsci/github-oauth-plugin/pull/72
[#73]: https://github.com/jenkinsci/github-oauth-plugin/pull/73
[JENKINS-16350]: https://issues.jenkins-ci.org/browse/JENKINS-16350
[JENKINS-34896]: https://issues.jenkins-ci.org/browse/JENKINS-34896
[JENKINS-39200]: https://issues.jenkins-ci.org/browse/JENKINS-39200

# Version 0.24 (Released May 26, 2016)

- Bugfix [JENKINS-34775][JENKINS-34775] Don't cast inconvertible un/pw token.
  ([pull request #56][#56])
- Bugfix [JENKINS-33883][JENKINS-33883] by allowing `.*/cc.xml` instead of only
  root one. ([pull request #51][#52])
- Bugfix loading orgs as groups when orgs contain no teams. ([pull request
  #54][#54])
- Correct spelling of GitHub and committer. (pull requests [#53][#53] and
  [#55][#55])

[#52]: https://github.com/jenkinsci/github-oauth-plugin/pull/52
[#53]: https://github.com/jenkinsci/github-oauth-plugin/pull/53
[#54]: https://github.com/jenkinsci/github-oauth-plugin/pull/54
[#55]: https://github.com/jenkinsci/github-oauth-plugin/pull/55
[#56]: https://github.com/jenkinsci/github-oauth-plugin/pull/56
[JENKINS-33883]: https://issues.jenkins-ci.org/browse/JENKINS-33883
[JENKINS-34775]: https://issues.jenkins-ci.org/browse/JENKINS-34775

# Version 0.23 (Released May 1, 2016)

- Encrypt client secret in stored settings ([pull request #51][#51])

[#51]: https://github.com/jenkinsci/github-oauth-plugin/pull/51

# Version 0.22.2 (Released July 25, 2015)

- The wiki page was having issues rendering plugin information. Unless I
  renamed it back (tracked by [JENKINS-29636][JENKINS-29636]). I renamed the
  wiki page back to "Github OAuth Plugin" so plugin info would be rendered. I
  released 0.22.2 to revert release 0.22.1.


# Version 0.22.1 (Released July 25, 2015)

- I renamed the wiki page to "Github Authentication Plugin" which caused the
  plugin to disappear from the update center (tracked by
  [JENKINS-29636][JENKINS-29636]). I released the plugin with the new wiki link.

[JENKINS-29636]: https://issues.jenkins-ci.org/browse/JENKINS-29636

# Version 0.22 (Released July 24, 2015)

- Bugfix Java 7 compatibility. The plugin now compiles and tests with Java 7
  ([pull request #42][#42])
- Scripting feature: equals() method available for idempotent groovy
  configuration ([pull request #43][#43])
- Allow limited oauth scopes ([pull request #45][#45])
- Allow Jenkins email to be set using GitHub private email ([pull request
- #47][#47])
- Private GitHub organization memberships can be used for authorization ([pull
  request #48][#48])

[#42]: https://github.com/jenkinsci/github-oauth-plugin/pull/42
[#43]: https://github.com/jenkinsci/github-oauth-plugin/pull/43
[#45]: https://github.com/jenkinsci/github-oauth-plugin/pull/45
[#47]: https://github.com/jenkinsci/github-oauth-plugin/pull/47
[#48]: https://github.com/jenkinsci/github-oauth-plugin/pull/48

# Version 0.21.2 (Released July 20, 2015)

- Bugfix migrating settings from plugin 0.20 to 0.21+ ([pull request #46][#46])
- Improved README ([pull request #44][#44])
- Improved code style by fixing white space ([pull request #40][#40])

[#40]: https://github.com/jenkinsci/github-oauth-plugin/pull/40
[#44]: https://github.com/jenkinsci/github-oauth-plugin/pull/44
[#46]: https://github.com/jenkinsci/github-oauth-plugin/pull/46

# Version 0.21.1 (Released July 12, 2015)

- Add support for allowing anonymous ViewStatus permission ([pull request
  #29][#29])

[#29]: https://github.com/jenkinsci/github-oauth-plugin/pull/29

# Version 0.21 (Released July 11, 2015)

- Fewer github api calls for performance ([pull request #27][#27])
- Fix for when user enters a badly formed github url for repo ([pull request
  #32][#32])
- Make Github OAuth scopes configurable in Security Realm of Global Security
  configuration ([pull request #35][#35])
- Default GitHub OAuth scope is now read:org ([pull request #39][#39])
- Include GitHub teams as groups when doing matrix based authorization
  strategies ([pull request #41][#41])
- Allow username and GitHub Personal Access Token to be used to access Jenkins
  API instead of requiring a Jenkins token to be generated ([pull request
  #37][#37])

[#27]: https://github.com/jenkinsci/github-oauth-plugin/pull/27
[#32]: https://github.com/jenkinsci/github-oauth-plugin/pull/32
[#35]: https://github.com/jenkinsci/github-oauth-plugin/pull/35
[#37]: https://github.com/jenkinsci/github-oauth-plugin/pull/37
[#39]: https://github.com/jenkinsci/github-oauth-plugin/pull/39
[#41]: https://github.com/jenkinsci/github-oauth-plugin/pull/41

# Version 0.20 (Released Sept 30, 2014)

- Minor code comments and updated GitHub API dependency.

# Version 0.19 (Released July 2, 2014)

- Honor proxy configuration ([pull request #15][#15])
- Flag to allow authenticated users to create new jobs ([pull request #21][#21])
- `SecurityListener` callback

[#15]: https://github.com/jenkinsci/github-oauth-plugin/pull/15
[#21]: https://github.com/jenkinsci/github-oauth-plugin/pull/21

# Version 0.15 (Released March 21, 2014)

- Don't attempt to set email address property for a user upon login ([pull
  request #14][#14])
- Use hasExplicitlyConfiguredAddress instead of getAddress(which scans all
  projects and builds to find users's email address) ([committed
  directly][bc21838]).
- Fix API token usage on Jenkins core 1.551 ([pull request #18][#18])

[#14]: https://github.com/jenkinsci/github-oauth-plugin/pull/14
[#18]: https://github.com/jenkinsci/github-oauth-plugin/pull/18
[bc21838]: https://github.com/jenkinsci/github-oauth-plugin/commit/bc21838bb0e28a8219086d0a28170305c38b6516

# Version 0.14 (Released July 11, 2013)

- don't overwrite the e-mail address from GitHub if one is already set ([pull
  request #4][#4])
- fixed an NPE ([pull request #10][#10])
- Caching of the org/user mapping ([pull request #3][#3])

[#3]: https://github.com/jenkinsci/github-oauth-plugin/pull/3
[#4]: https://github.com/jenkinsci/github-oauth-plugin/pull/4
[#10]: https://github.com/jenkinsci/github-oauth-plugin/pull/10

# Version 0.12 (Released June 13, 2012)

- Removed the GitHub V2 API dependency.

# Version 0.10 (Released March 4, 2012)

- Thanks to virtix for reporting a bug with the plugin not working with github
  enterprise.
- Note that you also have to upgrade the github-api plugin to version 1.17

# Version 0.9 (Released January 8, 2012)

- Thanks to Kohsuke Kawaguchi for several commits that allow github
  organizations to be specified using the matrix-based security.

# Version 0.8.1 (Released November 1, 2011)

- Fix the custom XStream Converter to allow the configurations to be saved
  correctly.

# Version 0.8 (Released November 1, 2011)

- Use custom XStream Converter to let < 0.7 configurations to still work.

# Version 0.7 (Released October 29, 2011)

- Adds support for Github Enterprise/Firewall installs.

# Version 0.6 (Released September 17, 2011)

- Adds checkbox to the AuthorizationStrategy configuration page to enable the
  anonymous read permission. (default is false: no anonymous reads).

# Version 0.5 (Released September 10, 2011)

- Fixes a problem where all users of the plugin would see a stack trace instead
  of Jenkins. The regex for detecting the github-webhook url was reworked to
  support that text appearing anywhere in the request URI.

# Version 0.4 (Released September 9, 2011)

- Thanks to vkravets for testing and contributing a patch to fix the regex so
  that it actually works for the github-wehook.

# Version 0.3 (Released September 8, 2011)

- Adds support for github-plugin's /github-webhook which can be enabled to allow
  anonymous READ access to this url. This permits a post commit hook in Github
  to notify Jenkins to build the related projects.

# Version 0.2 (Released July 25, 2011)

- Fixes serialization issue that prevented plugin from working after Jenkins was
  restarted.

# Version 0.1 (Released July 16, 2011)
