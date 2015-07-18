# How to contribute

All contributions to the GitHub OAuth Plugin are welcome.  This project runs
completely off of pull requests and code review.  There are a couple ways of
contributing.  This document serves as helpful guidelines to contributing and
isn't necessarily the full scope of available ways to contribute.

### Contribute code

1. Fork the project.
2. Create a feature or bugfix branch.
3. Commit your fix or feature.  Be sure to reference any related Jenkins issues
   in the commit message surrounded by square brackets.  e.g. `[JENKINS-12345]`
4. Create a pull request.

Please keep in mind that pull requests tend to stay open for a week or two.
This allows sufficient time for interested individuals to code review open pull
requests.

What sort of code could use contributing?

* Working on [open issues][issue-open].
* Unit tests - there simply aren't enough so writing unit tests alone is a plus.
* Adding code coverage metrics such as cobertura.
* Javadoc - it would be nice if Javadoc was complete.

### Contribute code reviews

Review [open pull requests][pr-open].  When reviewing, a simple `:+1:` comment
is good enough.  Make a best effort at catching bugs.  For extra credit, build
the plugin and manually test it yourself.  Things to look out for:

* Potential bugs with the way methods are called.
* Missing unit tests and perhaps suggestion on improving unit tests.
* Code style.
* Not mixing tabs with spaces.  All indentation should be spaces only.  Typical
  indentation is 4 spaces.

The current maintainers make a best effort to build and test the plugin manually
before merging a pull request.

### File issues or comment

Filing new issues and commenting on existing issues is a great help for
validating or debunking potential bug reports.

* [All issues][issue-all]
* [Open issues][issue-open]

[issue-all]: https://issues.jenkins-ci.org/browse/JENKINS-29373?jql=project%20%3D%20JENKINS%20AND%20component%20%3D%20github-oauth-plugin
[issue-open]: https://issues.jenkins-ci.org/browse/JENKINS-29373?jql=project%20%3D%20JENKINS%20AND%20status%20in%20%28Open%2C%20%22In%20Progress%22%2C%20Reopened%29%20AND%20component%20%3D%20github-oauth-plugin
[pr-open]: https://github.com/jenkinsci/github-oauth-plugin/pulls
