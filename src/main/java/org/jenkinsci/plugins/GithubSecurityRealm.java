
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.SecurityRealm.SecurityComponents;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
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
		 
		 return new HttpResponse() {
			
			public void generateResponse(StaplerRequest req, StaplerResponse rsp,
					Object node) throws IOException, ServletException {
				
				
//				rsp.sendRedirect2("https://github.com/login/oauth/authorize&client_id=" + clientID);
				
				rsp.sendRedirect2("https://github.com/login/oauth/authorize");
				
			}
		};
		 
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
