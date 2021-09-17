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

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.util.Secret;
import org.jenkinsci.Symbol;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Remembers the access token used to connect to the Github server
 *
 * @since TODO
 */
public class GithubAccessTokenProperty extends UserProperty {
    private final Secret accessToken;

    public GithubAccessTokenProperty(String accessToken) {
        this.accessToken = Secret.fromString(accessToken);
    }

    public @NonNull Secret getAccessToken() {
        return accessToken;
    }

    @Extension
    @Symbol("githubAccessToken")
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @Override
        public boolean isEnabled() {
            // does not show elements in /<user>/configure/
            return false;
        }

        @Override
        public UserProperty newInstance(User user) {
            // no default property
            return null;
        }
    }
}
