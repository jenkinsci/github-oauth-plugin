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
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class GithubSecretStorageTest {

    @Test
    void correctBehavior(JenkinsRule j) {
        User.getById("alice", true);
        User.getById("bob", true);

        String secret = "$3cR3t";

        assertFalse(GithubSecretStorage.contains(retrieveUser()));
        assertNull(GithubSecretStorage.retrieve(retrieveUser()));

        assertFalse(GithubSecretStorage.contains(retrieveOtherUser()));

        GithubSecretStorage.put(retrieveUser(), secret);

        assertTrue(GithubSecretStorage.contains(retrieveUser()));
        assertFalse(GithubSecretStorage.contains(retrieveOtherUser()));

        assertEquals(secret, GithubSecretStorage.retrieve(retrieveUser()));
    }

    private static User retrieveUser() {
        return User.getById("alice", false);
    }

    private static User retrieveOtherUser() {
        return User.getById("bob", false);
    }

    @Test
    void correctBehaviorEvenAfterRestart(JenkinsRule j) throws Throwable {
        final String secret = "$3cR3t";

        User.getById("alice", true).save();
        User.getById("bob", true).save();

        assertFalse(GithubSecretStorage.contains(retrieveUser()));
        assertNull(GithubSecretStorage.retrieve(retrieveUser()));

        assertFalse(GithubSecretStorage.contains(retrieveOtherUser()));

        GithubSecretStorage.put(retrieveUser(), secret);

        assertTrue(GithubSecretStorage.contains(retrieveUser()));
        assertFalse(GithubSecretStorage.contains(retrieveOtherUser()));

        assertEquals(secret, GithubSecretStorage.retrieve(retrieveUser()));

        j.restart();

        assertTrue(GithubSecretStorage.contains(retrieveUser()));
        assertFalse(GithubSecretStorage.contains(retrieveOtherUser()));

        assertEquals(secret, GithubSecretStorage.retrieve(retrieveUser()));
    }
}
