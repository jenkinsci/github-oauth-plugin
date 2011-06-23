/**
 * The person or persons who have associated work with this document (the
 * "Dedicator" or "Certifier") hereby either (a) certifies that, to the best of
 * his knowledge, the work of authorship identified is in the public domain of
 * the country from which the work is published, or (b) hereby dedicates
 * whatever copyright the dedicators holds in the work of authorship identified
 * below (the "Work") to the public domain. A certifier, moreover, dedicates any
 * copyright interest he may have in the associated work, and for these
 * purposes, is described as a "dedicator" below.
 *
 * A certifier has taken reasonable steps to verify the copyright status of this
 * work. Certifier recognizes that his good faith efforts may not shield him
 * from liability if in fact the work certified is not in the public domain.
 *
 * Dedicator makes this dedication for the benefit of the public at large and to
 * the detriment of the Dedicator's heirs and successors. Dedicator intends this
 * dedication to be an overt act of relinquishment in perpetuity of all present
 * and future rights under copyright law, whether vested or contingent, in the
 * Work. Dedicator understands that such relinquishment of all rights includes
 * the relinquishment of all rights to enforce (by lawsuit or otherwise) those
 * copyrights in the Work.
 *
 * Dedicator recognizes that, once placed in the public domain, the Work may be
 * freely reproduced, distributed, transmitted, used, modified, built upon, or
 * otherwise exploited by anyone for any purpose, commercial or non-commercial,
 * and in any way, including by methods that have not yet been invented or
 * conceived.
 */
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import net.sf.json.JSONObject;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

/**
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses a MySQL
 * database as the source of authentication information.
 * 
 * @author Alex Ackerman
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
