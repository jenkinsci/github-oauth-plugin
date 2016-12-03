# Jenkins GitHub OAuth Plugin

* License: [MIT Licensed](LICENSE.txt)
* Read more: [GitHub OAuth Plugin wiki page][wiki]
* Latest build: [![Build Status][build-image]][build-link]
* [Contributions are welcome](CONTRIBUTING.md).

# Overview

The GitHub OAuth plugin provides a means of securing a Jenkins instance by
offloading authentication and authorization to GitHub.  The plugin authenticates
by using a [GitHub OAuth Application][github-wiki-oauth].  It can use multiple
authorization strategies for authorizing users.  GitHub users are surfaced as
Jenkins users for authorization.  GitHub organizations and teams are surfaced as
Jenkins groups for authorization.  This plugin supports GitHub Enterprise.

More comprehensive documentation is listed on the [wiki page][wiki].

# Building the plugin from master

### Prerequisites

This plugin was last compiled with the following versions.

* Ubuntu 16.04.1 LTS
* Apache Maven 3.3.9
* Java version: 1.7.0_79, vendor: Oracle Corporation

Newer/older versions may work.

### Packaging HPI for Jenkins

To create `github-oauth.hpi` which is the plugin that would be loaded in Jenkins
execute the following command.

    mvn clean package

The command assumes both Maven and Java are in your `$PATH` and that you have
`$JAVA_HOME` set up.

[build-image]: https://jenkins.ci.cloudbees.com/buildStatus/icon?job=plugins/github-oauth-plugin
[build-link]: https://jenkins.ci.cloudbees.com/job/plugins/job/github-oauth-plugin/
[github-wiki-oauth]: https://developer.github.com/v3/oauth/
[wiki]: https://wiki.jenkins-ci.org/display/JENKINS/Github+OAuth+Plugin
