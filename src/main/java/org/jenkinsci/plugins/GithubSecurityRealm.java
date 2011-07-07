
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

import java.io.IOException;
import java.util.logging.Logger;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
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



	@Override
	public SecurityComponents createSecurityComponents() {
		return new SecurityComponents(
			 // copied from the openid-plugin
				 new AuthenticationManager() {
		                public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		                    if (authentication instanceof AnonymousAuthenticationToken
		                    ||  authentication instanceof UsernamePasswordAuthenticationToken)
		                        return authentication;
		                    throw new BadCredentialsException("Unexpected authentication type: "+authentication);
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

		/* (non-Javadoc)
		 * @see hudson.model.Descriptor#configure(org.kohsuke.stapler.StaplerRequest, net.sf.json.JSONObject)
		 */
		@Override
		public boolean configure(StaplerRequest req, JSONObject json)
				throws FormException {
			// TODO Auto-generated method stub
			return super.configure(req, json);
		}

		/* (non-Javadoc)
		 * @see hudson.model.Descriptor#save()
		 */
		@Override
		public synchronized void save() {
			// TODO Auto-generated method stub
			super.save();
		}

		/* (non-Javadoc)
		 * @see hudson.model.Descriptor#load()
		 */
		@Override
		public synchronized void load() {
			// TODO Auto-generated method stub
			super.load();
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

//        connectionString = "jdbc:mysql://" + myServer + "/" +
//                myDatabase;
//        LOGGER.info("GithubSecurity: Connection String - " + connectionString);
//        Connection conn = null;
//        try
//        {
//            // Connect to the database
//            Class.forName("com.mysql.jdbc.Driver").newInstance();
//            conn = DriverManager.getConnection(connectionString,
//                    myUsername, myPassword);
//            LOGGER.info("GithubSecurity: Connection established.");
//
//            // Prepare the statement and query the user table
//            // TODO: Review userQuery to see if there's a better way to do this
//            String userQuery = "SELECT * FROM " + myDataTable + " WHERE " +
//                    myUserField + " = ?";
//            PreparedStatement statement = conn.prepareStatement(userQuery);
//            //statement.setString(1, myDataTable);
//            //statement.setString(2, myUserField);
//            statement.setString(1, username);
//            ResultSet results = statement.executeQuery();
//            LOGGER.fine("GithubSecurity: Query executed.");
//
//            // Grab the first result (should be only user returned)
//            if (results.first())
//            {
//                // Build the user detail
//                Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
//                groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
//                user = new GithubUserDetail(username, results.getString(myPassField),
//                            true, true, true, true, 
//                            groups.toArray(new GrantedAuthority[groups.size()]));
//            }
//            else
//            {
//                LOGGER.warning("GithubSecurity: Invalid Username or Password");
//                throw new UsernameNotFoundException("MySQL: User not found");
//            }
//
//        }
//        catch (Exception e)
//        {
//            LOGGER.warning("GithubSecurity Realm Error: " + e.getLocalizedMessage());
//        }
//        finally
//        {
//            if (conn != null)
//            {
//                try
//                {
//                    conn.close();
//                    LOGGER.info("GithubSecurity: Connection closed.");
//                }
//                catch (Exception ex)
//                {
//                    /** Ignore any errors **/
//                }
//            }
//        }
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
