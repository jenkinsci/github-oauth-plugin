/**
 * 
 */
package org.jenkinsci.plugins;

import java.io.IOException;
import java.net.URI;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;

/**
 * @author mocleiri
 * 
 * to hold the authentication token from the github oauth process.
 *
 */
public class GithubAuthenticationToken extends AbstractAuthenticationToken {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private final String accessToken;

	public GithubAuthenticationToken(String accessToken) {
		
		super (new GrantedAuthority[] {});
		
		this.accessToken = accessToken;
	}

	/* (non-Javadoc)
	 * @see org.acegisecurity.Authentication#getCredentials()
	 */
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return null;
	}

	private String httpGet (String path) throws ClientProtocolException, IOException {
	
		HttpClient client = new DefaultHttpClient();
		
		String url = "https://api.github.com/" + path + "?access_token=" + accessToken;
		
		HttpResponse r = client.execute(new HttpGet(url));
		
		return EntityUtils.toString(r.getEntity());
		
	}
	
	
	/* (non-Javadoc)
	 * @see org.acegisecurity.Authentication#getPrincipal()
	 */
	public Object getPrincipal() {
		
		try {
			String json = httpGet("user");
			
			System.out.println(json);
			
		} catch (Exception e) {
			
			// fall through
		}		
		
		// TODO Auto-generated method stub
		return null;
	}

}
