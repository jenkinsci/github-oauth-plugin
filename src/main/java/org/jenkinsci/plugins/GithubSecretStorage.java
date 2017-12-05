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

import hudson.model.User;
import org.jfree.util.Log;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.IOException;

public class GithubSecretStorage {

    private GithubSecretStorage(){
        // no accessible constructor
    }

    public static boolean contains(@Nonnull User user) {
        return user.getProperty(GithubAccessTokenProperty.class) != null;
    }

    public static @CheckForNull String retrieve(@Nonnull User user) {
        GithubAccessTokenProperty property = user.getProperty(GithubAccessTokenProperty.class);
        if (property == null) {
            Log.debug("Cache miss for username: " + user.getId());
            return null;
        } else {
            Log.debug("Token retrieved using cache for username: " + user.getId());
            return property.getAccessToken().getPlainText();
        }
    }

    public static void put(@Nonnull User user, @Nonnull String accessToken) {
        Log.debug("Populating the cache for username: " + user.getId());
        try {
            user.addProperty(new GithubAccessTokenProperty(accessToken));
        } catch (IOException e) {
            Log.warn("Received an exception when trying to add the GitHub access token to the user: " + user.getId(), e);
        }
    }
}
