
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

/**
 * 
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses github oauth to verify the user can login.
 * 
 * This is based on the MySQLSecurityRealm from the mysql-auth-plugin written by Alex Ackerman.
 */
public class GithubSecurityRealm extends SecurityRealm 
{

    private String clientID;
	private String clientSecret; 


	@DataBoundConstructor
    public GithubSecurityRealm(String clientID, String clientSecret)
    {
		super();
		
		if (clientID == null || clientID.length() == 0)
			this.clientID = "2885d186c7c7a37d9a10";
		else	
			this.clientID = Util.fixEmptyAndTrim(clientID);
		
		if (clientSecret == null || clientSecret.length() == 0)
			this.clientSecret = "1593de427008eed6b5d76a9d8180b30f2036d276";
		else 
			this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
    	
    }
	
	

	/**
	 * @return the clientID
	 */
	public String getClientID() {
		return clientID;
	}



	/**
	 * @return the clientSecret
	 */
	public String getClientSecret() {
		return clientSecret;
	}



	public HttpResponse doCommenceLogin(@Header("Referer") final String referer) throws IOException {
		 
		return new HttpRedirect("https://github.com/login/oauth/authorize?client_id=" + clientID);
		
		 
	 }
	
	/**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
    	
    	
    	String code = request.getParameter("code");
    	
    	Log.info("test");
    	
    	HttpPost httpost = new HttpPost("https://github.com/login/oauth/access_token?" +
                "client_id="+clientID+"&" +
                "client_secret=" + clientSecret + "&" +
                "code=" + code);


       DefaultHttpClient httpclient = new DefaultHttpClient();
       
		org.apache.http.HttpResponse response = httpclient.execute(httpost);
		
        HttpEntity entity = response.getEntity();
        
        String content = EntityUtils.toString(entity);
        

        

        // When HttpClient instance is no longer needed, 
        // shut down the connection manager to ensure
        // immediate deallocation of all system resources
        httpclient.getConnectionManager().shutdown();        
        
        String accessToken = extractToken (content);
        
        SecurityContextHolder.getContext().setAuthentication(new GithubAuthenticationToken(accessToken));
    	
    	return HttpResponses.redirectToContextRoot();
    }
	
	
	private String extractToken(String content) {
		
		
			
			String parts[] = content.split("&");
			
			
			for (String part : parts) {
		
				if (content.contains("access_token")) {
					
					String tokenParts[] = part.split("=");
					
					return tokenParts[1];
				}
			
				// fall through
			}
			
			
	
			return null;
	}




   

    /* (non-Javadoc)
	 * @see hudson.security.SecurityRealm#allowsSignup()
	 */
	@Override
	public boolean allowsSignup() {
		return false;
	}



	@Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) {
                return authentication;
            }
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
                throw new UsernameNotFoundException(username);
            }
        });
    }

	

	@Override
	public String getLoginUrl() {
		
		return "securityRealm/commenceLogin";
	}



	@Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm>
    {
    
		private static DescriptorImpl instance = new DescriptorImpl();
		
        @Override
        public String getHelpFile() {
            return "/plugin/github-oauth/help/overview.html";
        }
        
        @Override
        public String getDisplayName() {
            return "Github Authentication Plugin";
        }
        
        

		
		public DescriptorImpl() {
			super();
			// TODO Auto-generated constructor stub
		}

		public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
			super(clazz);
			// TODO Auto-generated constructor stub
		}

		
        
			
        
    }

    
    
    	
    /**
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException
    {
        UserDetails user = null;
        String connectionString;
        
        if (true)
        	throw new UsernameNotFoundException("implemtnation required");

        return user;
    }

    /**
     *
     * @param groupname
     * @return
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     */
    @Override
    public GroupDetails loadGroupByGroupname(String groupname)
            throws UsernameNotFoundException, DataAccessException
    {
        LOGGER.warning("ERROR: Group lookup is not supported.");
        throw new UsernameNotFoundException("GithubSecurityRealm: Non-supported function");
    }

    

 
    /**
     * Logger for debugging purposes.
     */
    private static final Logger LOGGER =
            Logger.getLogger(GithubSecurityRealm.class.getName());

   

}
