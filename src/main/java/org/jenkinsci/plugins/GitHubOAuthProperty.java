package org.jenkinsci.plugins;

import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import net.sf.json.JSONObject;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.export.ExportedBean;

/**
 * UserProperty class which contains the github oauth ClientID and Client Secret
 * 
 * @author landir
 */
@ExportedBean(defaultVisibility = 999)
public class GitHubOAuthProperty extends UserProperty {

    public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

    private String clientId;
    
    private String clientSecret;
    
    public GitHubOAuthProperty() {
    }

    @DataBoundConstructor
    

    public GitHubOAuthProperty(String clientId, String clientSecret) {
		super();
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	public UserPropertyDescriptor getDescriptor() {
        return DESCRIPTOR;
    }

    @Exported
    public User getUser() {
        return user;
    }

   
   

    /**
	 * @return the clientId
	 */
    @Exported
	public String getClientId() {
		return clientId;
	}

	/**
	 * @param clientId the clientId to set
	 */
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	/**
	 * @return the clientSecret
	 */
	 @Exported
	public String getClientSecret() {
		return clientSecret;
	}

	/**
	 * @param clientSecret the clientSecret to set
	 */
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}




	public static final class DescriptorImpl extends UserPropertyDescriptor {
        public DescriptorImpl() {
            super(GitHubOAuthProperty.class);
        }

        @Override
        public String getDisplayName() {
            return "Twitter User Name";
        }
        
        

        @Override
        public GitHubOAuthProperty newInstance(StaplerRequest req, JSONObject formData)
                throws hudson.model.Descriptor.FormException {
            if (formData.has("twitterid")) {
                return req.bindJSON(GitHubOAuthProperty.class, formData);
            } else {
                return new GitHubOAuthProperty();
            }
        }

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }
    }
}
