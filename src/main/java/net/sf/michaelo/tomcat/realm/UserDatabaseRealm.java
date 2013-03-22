package net.sf.michaelo.tomcat.realm;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.naming.NamingException;

import org.apache.catalina.Group;
import org.apache.catalina.Role;
import org.apache.catalina.User;
import org.apache.catalina.UserDatabase;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.ietf.jgss.GSSCredential;

public class UserDatabaseRealm extends GssApiAwareRealm<UserDatabase> {
	
	private static final Log logger = LogFactory.getLog(UserDatabaseRealm.class);
	
	@Override
	public String getInfo() {
		return "net.sf.michaelo.realm.UserDatabaseRealm/0.9";
	}
	
	@Override
	protected String getName() {
		return "UserDatabaseRealm";
	}
	
	@Override
	protected Principal getPrincipal(String username, GSSCredential gssCredential) {
		 
		 UserDatabase database = null;
		
		try {
			database = lookupResource();
		} catch (NamingException e) {
			logger.error(String.format("Could not retrieve the UserDatabase '%s' from JNDI context", resourceName));
			throw new RuntimeException(String.format("Failed to retrieve resource '%s'", resourceName), e);
		}
		
		User user = database.findUser(username);
	        if(user == null) {
	            return null;
	        }

	        List<String> roles = new ArrayList<String>();
	        Iterator<?> uroles = user.getRoles();
	        while(uroles.hasNext()) {
	            Role role = (Role)uroles.next();
	            roles.add(role.getName());
	        }
	        Iterator<?> groups = user.getGroups();
	        while(groups.hasNext()) {
	            Group group = (Group)groups.next();
	            uroles = group.getRoles();
	            while(uroles.hasNext()) {
	                Role role = (Role)uroles.next();
	                roles.add(role.getName());
	            }
	        }
	        return new GenericPrincipal(this, username, user.getPassword(), roles, user);
	}

	public boolean hasRole(Principal principal, String role) {
        if( principal instanceof GenericPrincipal) {
            GenericPrincipal gp = (GenericPrincipal)principal;
            if(gp.getUserPrincipal() instanceof User) {
                principal = gp.getUserPrincipal();
            }
        }
        if(! (principal instanceof User) ) {
            //Play nice with SSO and mixed Realms
            return super.hasRole(principal, role);
        }
        if("*".equals(role)) {
            return true;
        } else if(role == null) {
            return false;
        }
        User user = (User)principal;
        
        UserDatabase database;
        try {
			database = (UserDatabase) lookupResource();
		} catch (NamingException e) {
			logger.error(String.format("Could not retrieve the UserDatabase '%s' from JNDI context", resourceName));
			throw new RuntimeException(String.format("Failed to retrieve resource '%s'", resourceName), e);
		}
        
        Role dbrole = database.findRole(role);
        if(dbrole == null) {
            return false; 
        }
        if(user.isInRole(dbrole)) {
            return true;
        }
        Iterator<?> groups = user.getGroups();
        while(groups.hasNext()) {
            Group group = (Group)groups.next();
            if(group.isInRole(dbrole)) {
                return true;
            }
        }
        return false;
    }

}
