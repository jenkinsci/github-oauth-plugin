/**
 The MIT License

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
package org.jenkinsci.plugins;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Uniquely identifies a repository on GitHub.
 *
 * This is a simplified version of the file
 * https://github.com/jenkinsci/github-plugin/blob/master/src/main/java/com/cloudbees/jenkins/GitHubRepositoryName.java
 *
 * It has been duplicated to avoid introducing a dependency on "github-plugin"
 *
 * @author Kohsuke Kawaguchi
 */
public class GitHubRepositoryName {

    private static final Pattern[] URL_PATTERNS = {
        /**
         * The first set of patterns extract the host, owner and repository names
         * from URLs that include a '.git' suffix, removing the suffix from the
         * repository name.
         */
        Pattern.compile("git@(.+):([^/]+)/([^/]+)\\.git"),
        Pattern.compile("https?://[^/]+@([^/]+)/([^/]+)/([^/]+)\\.git"),
        Pattern.compile("https?://([^/]+)/([^/]+)/([^/]+)\\.git"),
        Pattern.compile("git://([^/]+)/([^/]+)/([^/]+)\\.git"),
        Pattern.compile("ssh://git@([^/]+)/([^/]+)/([^/]+)\\.git"),
        /**
         * The second set of patterns extract the host, owner and repository names
         * from all other URLs. Note that these patterns must be processed *after*
         * the first set, to avoid any '.git' suffix that may be present being included
         * in the repository name.
         */
        Pattern.compile("git@(.+):([^/]+)/([^/]+)/?"),
        Pattern.compile("https?://[^/]+@([^/]+)/([^/]+)/([^/]+)/?"),
        Pattern.compile("https?://([^/]+)/([^/]+)/([^/]+)/?"),
        Pattern.compile("git://([^/]+)/([^/]+)/([^/]+)/?"),
        Pattern.compile("ssh://git@([^/]+)/([^/]+)/([^/]+)/?")
    };

    /**
     * Create {@link GitHubRepositoryName} from URL
     *
     * @param url
     *            must be non-null
     * @return parsed {@link GitHubRepositoryName} or null if it cannot be
     *         parsed from the specified URL
     */
    public static GitHubRepositoryName create(final String url) {
        LOGGER.log(Level.FINE, "Constructing from URL {0}", url);
        for (Pattern p : URL_PATTERNS) {
            Matcher m = p.matcher(url.trim());
            if (m.matches()) {
                LOGGER.log(Level.FINE, "URL matches {0}", m);
                GitHubRepositoryName ret = new GitHubRepositoryName(m.group(1), m.group(2),
                        m.group(3));
                LOGGER.log(Level.FINE, "Object is {0}", ret);
                return ret;
            }
        }
        LOGGER.log(Level.WARNING, "Could not match URL {0}", url);
        return null;
    }

    public final String host, userName, repositoryName;

    public GitHubRepositoryName(String host, String userName, String repositoryName) {
        this.host           = host;
        this.userName       = userName;
        this.repositoryName = repositoryName;
    }

    @Override
    public String toString() {
        return "GitHubRepository[host="+host+",username="+userName+",repository="+repositoryName+"]";
    }

    private static final Logger LOGGER = Logger.getLogger(GitHubRepositoryName.class.getName());

}
