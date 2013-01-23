Jenkins Github OAuth Plugin
============================

Read more: [http://wiki.jenkins-ci.org/display/JENKINS/Github+OAuth+Plugin](http://wiki.jenkins-ci.org/display/JENKINS/Github+OAuth+Plugin)

Overview
--------

The idea behind this plugin is that github already knows which users are committers on specific projects.

So we should be able to have an authentication process using OAuth that allows users to login to jenkins using their github credentials.

There are two key parts to this plugin:

A. GithubSecurityRealm: 

This handles the authentication and acquisition of the github oauth token for the connecting user.

This takes the client id and client secret from the application registration here: https://github.com/settings/applications/new

The entry should look like this:

Main URL: http://127.0.0.1:8080
Callback URL: http://127.0.0.1:8080/securityRealm/finishLogin

With 127.0.0.1:8080 replaced with the hostname and port of your jenkins instance.


B. GithubAuthorizationStrategy:

This defines:

1. Comma separated list of users that should be given admin privileges.

2. Comma separated list of organizations whose members should be given read and build permissions on the jobs.

3. Check box to give other authenticated users read permission.

4. Check box to allow anonymous users READ permission for the /github-webhook.  
This only has meaning if the github-plugin is installed and the remote github repository post commit hook has been setup accordingly.

5. Check box to allow anonymous users READ permission for the /job/*/badge/icon [embeddable build status icon](https://wiki.jenkins-ci.org/display/JENKINS/Embeddable+Build+Status+Plugin).

The plugin works but there are still some areas like form validation that need work.  And some other cases where exceptions are thrown when perhaps there is a better way.

Notes:

The user must be a public member in the organizations that are declared.

License
-------

	(The MIT License)

	Copyright (c) 2011 Michael O'Cleirigh

	Permission is hereby granted, free of charge, to any person obtaining
	a copy of this software and associated documentation files (the
	'Software'), to deal in the Software without restriction, including
	without limitation the rights to use, copy, modify, merge, publish,
	distribute, sublicense, and/or sell copies of the Software, and to
	permit persons to whom the Software is furnished to do so, subject to
	the following conditions:

	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
	IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
	CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
	TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

