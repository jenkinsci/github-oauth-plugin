/**
 * 
 */
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.diagnosis.OldDataMonitor;
import hudson.model.Descriptor;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.util.RobustReflectionConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

/**
 * @author mocleiri
 * 
 * 
 * 
 */
public class GithubAuthorizationStrategy extends AuthorizationStrategy {

	private static final String ORGANIZATION_NAMES = "organizationNames";
	private static final String AUTHENTICATED_USER_READ_PERMISSION = "authenticatedUserReadPermission";
	private static final String ADMIN_USER_NAMES = "adminUserNames";

	private static class GithubRequireOrganizationMembershipACL extends ACL {

		private final List<String> organizationNameList;
		private final List<String> adminUserNameList;
		private final boolean authenticatedUserReadPermission;

		
		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * hudson.security.ACL#hasPermission(org.acegisecurity.Authentication,
		 * hudson.security.Permission)
		 */
		@Override
		public boolean hasPermission(Authentication a, Permission permission) {

		
			if (a != null && a instanceof GithubAuthenticationToken) {
				
				GithubAuthenticationToken authenticationToken = (GithubAuthenticationToken) a;
				
				String candidateName = a.getName();
				
				if (adminUserNameList.contains(candidateName)) 
					// if they are an admin then they have permission
					return true;
					

				for (String organizationName : this.organizationNameList) {

					if (authenticationToken.hasOrganizationPermission(
							candidateName, organizationName)) {

						String[] parts = permission.getId().split("\\.");

						String test = parts[parts.length-1].toLowerCase();

						if (test.equals("read") || test.equals("build"))
							// check the permission
							return true;
					}

				}

				// no match.
				return false;
				
			}
			else {
				
				String p = a.getName();

				if (p.equals("anonymous"))
					return false;

				if (p.equals(SYSTEM.getPrincipal())) {
					return true;
				}

				if (adminUserNameList.contains(p)) {
					// if they are an admin then they have permission
					return true;
				} else {
					if (authenticatedUserReadPermission) {

						String[] parts = permission.getId().split("\\.");
						if (parts[parts.length - 1].toLowerCase().equals("read"))

							// if we support authenticated read and this is a read
							// request we allow it
							return true;
					}
				}
				
				return false;

			}
			
			

		}

		public GithubRequireOrganizationMembershipACL(
				String adminUserNames,
				String organizationNames,
				boolean authenticatedUserReadPermission) {
			super();
			this.authenticatedUserReadPermission = authenticatedUserReadPermission;
			

			this.adminUserNameList = new LinkedList<String>();

			String[] parts = adminUserNames.split(",");

			for (String part : parts) {
				adminUserNameList.add(part);
			}

			this.organizationNameList = new LinkedList<String>();

			parts = organizationNames.split(",");

			for (String part : parts) {
				organizationNameList.add(part);
			}
			
		}

	}

	private final String adminUserNames;

	private final boolean authenticatedUserReadPermission;

	private final String organizationNames;

	
	/**
	 * 
	 */
	@DataBoundConstructor
	public GithubAuthorizationStrategy(String adminUserNames,
			boolean authenticatedUserReadPermission, String organizationNames) {
		super();
		this.adminUserNames = adminUserNames;
		this.authenticatedUserReadPermission = authenticatedUserReadPermission;
		this.organizationNames = organizationNames;

		rootACL = new GithubRequireOrganizationMembershipACL(this.adminUserNames, this.organizationNames,
				this.authenticatedUserReadPermission);
	}

	private ACL rootACL = null;
	/*
	 * (non-Javadoc)
	 * 
	 * @see hudson.security.AuthorizationStrategy#getRootACL()
	 */
	@Override
	public ACL getRootACL() {

	return rootACL;

}

	

	/*
	 * (non-Javadoc)
	 * 
	 * @see hudson.security.AuthorizationStrategy#getGroups()
	 */
	@Override
	public Collection<String> getGroups() {
		return new ArrayList<String>(0);
	}



	



	/**
	 * @return the adminUserNames
	 */
	public String getAdminUserNames() {
		return adminUserNames;
	}



	/**
	 * @return the authenticatedUserReadPermission
	 */
	public boolean isAuthenticatedUserReadPermission() {
		return authenticatedUserReadPermission;
	}



	/**
	 * @return the organizationNames
	 */
	public String getOrganizationNames() {
		return organizationNames;
	}







	@Extension
	public static final class DescriptorImpl extends
			Descriptor<AuthorizationStrategy> {
		
		public String getDisplayName() {
			return "Github Commiter Authorization Strategy";
		}

		public String getHelpFile() {
			return "/help-authorization-strategy.html";
		}

//		
//		@Override
//		public GithubAuthorizationStrategy newInstance(StaplerRequest req,
//				JSONObject formData) throws FormException {
//
//			String adminUserNames = formData.getString(ADMIN_USER_NAMES);
//			
//			boolean authorizedReadPermission = formData
//					.getBoolean(AUTHENTICATED_USER_READ_PERMISSION);
//
//			String organizationNames = formData.getString(ORGANIZATION_NAMES);
//
//			return new GithubAuthorizationStrategy(adminUserNames,
//					authorizedReadPermission, organizationNames);
//		}

	}
	
	public static class ConverterImpl implements Converter {
        public boolean canConvert(Class type) {
            if (type==GithubAuthorizationStrategy.class)
            	return true;
            else
            	return false;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        	GithubAuthorizationStrategy strategy = (GithubAuthorizationStrategy)source;

            // Output in alphabetical order for readability.
        	
        	writer.startNode(ADMIN_USER_NAMES);
        	writer.setValue(strategy.getAdminUserNames());
        	writer.endNode();
        	
        	writer.startNode(ORGANIZATION_NAMES);
        	writer.setValue(strategy.getOrganizationNames());
        	writer.endNode();
        	
        	writer.startNode(AUTHENTICATED_USER_READ_PERMISSION);
        	writer.setValue(String.valueOf(strategy.isAuthenticatedUserReadPermission()));
        	writer.endNode();
        	

        }

        public Object unmarshal(HierarchicalStreamReader reader, final UnmarshallingContext context) {

                reader.moveDown();

                String adminUserNames = reader.getValue();
                
                reader.moveUp();
                
                reader.moveDown();
                
                String organizationNames = reader.getValue();
                
                reader.moveUp();
                
                reader.moveDown();
                
                boolean authorizedReadPermission = Boolean.valueOf(reader.getValue());
         
			return new GithubAuthorizationStrategy(adminUserNames,
					authorizedReadPermission, organizationNames);
        }

      
    }
}
