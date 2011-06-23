
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

import java.util.logging.Logger;

import net.sf.json.JSONObject;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

/**
 * 
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses github oauth to verify the user can login.
 * 
 * This is based on the MySQLSecurityRealm from the mysql-auth-plugin written by Alex Ackerman.
 */
public class GithubSecurityRealm extends AbstractPasswordBasedSecurityRealm
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
     * Authenticates the specified user using the password against the stored
     * database configuration.
     *
     * @param username      The username to lookup
     * @param password      The password to use for authentication
     * @return              A UserDetails object containing information about
     *                      the user.
     * @throws AuthenticationException  Thrown when the username/password do
     *                                  not match stored values.
     */
    @Override
    protected UserDetails authenticate(String username, String password)
            throws AuthenticationException
    {
        UserDetails userDetails = null;

        if (true)
        	throw new GithubAuthenticationException("implementation is required.");
        

//        connectionString = "jdbc:mysql://" + myServer + "/" +
//                myDatabase;
//        LOGGER.fine("GithubSecurity: Connection String - " + connectionString);
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
//            statement.setString(1, myDataTable);
//            LOGGER.fine("GithubSecurity: Query Info - ");
//            LOGGER.fine("- Table: " + myDataTable);
//            LOGGER.fine("- User Field: " + myUserField);
//            LOGGER.fine("- Username: " + myUsername);
//            //statement.setString(2, myUserField);
//            statement.setString(1, username);
//            ResultSet results = statement.executeQuery();
//            LOGGER.fine("GithubSecurity: Query executed.");
//
//            if (results.first())
//            {
//                String storedPassword = results.getString(myPassField);
//                Cipher cipher;
//                if (encryption.equals(Cipher.CRYPT))
//                {
//                    String salt = storedPassword.substring(0, 2);
//                    cipher = new Cipher(encryption, salt);
//                }
//                else
//                {
//                    cipher = new Cipher(encryption);
//                }
//                String encryptedPassword = cipher.encode(password.trim());
//                LOGGER.fine("Encrypted Password: " + encryptedPassword);
//                LOGGER.fine("Stored Password: " + storedPassword);
//                if (!storedPassword.equals(encryptedPassword))
//                {
//                    LOGGER.warning("GithubSecurity: Invalid Username or Password");
//                    throw new GithubAuthenticationException("Invalid Username or Password");
//                }
//                else
//                {
//                    // Password is valid.  Build UserDetail
//                    Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
//                    groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
//                    userDetails = new GithubUserDetail(username, encryptedPassword,
//                            true, true, true, true,
//                            groups.toArray(new GrantedAuthority[groups.size()]));
//                }
//            }
//            else
//            {
//                LOGGER.warning("GithubSecurity: Invalid Username or Password");
//                throw new GithubAuthenticationException("Invalid Username or Password");
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

        return userDetails;
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

    class Authenticator extends AbstractUserDetailsAuthenticationProvider
    {

        @Override
        protected void additionalAuthenticationChecks(UserDetails userDetails,
                UsernamePasswordAuthenticationToken authentication)
                throws AuthenticationException {
            // Assumed to be done in the retrieveUser method
        }

        @Override
        protected UserDetails retrieveUser(String username,
                UsernamePasswordAuthenticationToken authentication)
                throws AuthenticationException {
            return GithubSecurityRealm.this.authenticate(username,
                    authentication.getCredentials().toString());
        }

    }

 
    /**
     * Logger for debugging purposes.
     */
    private static final Logger LOGGER =
            Logger.getLogger(GithubSecurityRealm.class.getName());

   

}
