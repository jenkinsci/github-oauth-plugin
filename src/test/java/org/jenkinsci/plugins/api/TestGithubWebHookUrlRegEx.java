/**
 The MIT License

Copyright (c) 2011 Michael O'Cleirigh

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
package org.jenkinsci.plugins.api;

import junit.framework.TestCase;

/**
 * @author mocleiri
 *
 */
public class TestGithubWebHookUrlRegEx extends TestCase {

	/**
	 * 
	 */
	public TestGithubWebHookUrlRegEx() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param name
	 */
	public TestGithubWebHookUrlRegEx(String name) {
		super(name);
		// TODO Auto-generated constructor stub
	}
	
	
	public void testRootedWebHookRegEx() {
		
		String regex = ".*github-webhook.*";
		
		String url = "/github-webhook";
		
		assertTrue(url.matches(regex));
		
		String questionUrl = "/github-webhook/?";
		
		assertTrue(questionUrl.matches(regex));
		
		String nested= "/nesting/github-webhook";

		assertTrue(nested.matches(regex));
		
		String questionNested= "/nesting/github-webhook";
		
		assertTrue(questionNested.matches(regex));
		
	}

}
