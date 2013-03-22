package net.sf.michaelo.tomcat.realm;

import java.security.Principal;

import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.catalina.ServerFactory;
import org.apache.catalina.core.StandardServer;
import org.apache.catalina.realm.RealmBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.naming.ContextBindings;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

public abstract class GssApiAwareRealm<T> extends RealmBase {

	private static final Log logger = LogFactory.getLog(GssApiAwareRealm.class);

	protected boolean localResource;
	protected String resourceName;
	
	private T resource;
	
	public void setLocalResource(boolean localResource) {
		this.localResource = localResource;
	}

	public void setResourceName(String resourceName) {
		this.resourceName = resourceName;
	}

	abstract protected Principal getPrincipal(String username, GSSCredential gssCredential);
	
	@Override
	protected String getPassword(String password) {
		throw new UnsupportedOperationException("This method is not supported by this realm");
	}

	@Override
	protected Principal getPrincipal(String username) {
		return getPrincipal(username, null);
	}

	/**
	 * 
	 * @param gssContext
	 * @param storeDelegatedCredential
	 * @return the retrieved principal
	 * @throws RuntimeException
	 *             wraps GSSException and NamingException
	 */
	public Principal authenticate(GSSContext gssContext, boolean storeDelegatedCredential) {

		try {

			GSSName gssName = gssContext.getSrcName();

			if (gssName != null) {

				GSSCredential gssCredential = null;
				if (storeDelegatedCredential) {
					if (gssContext.getCredDelegState()) {
						gssCredential = gssContext.getDelegCred();
					} else
						logger.debug(String.format("Credential of '%s' is not delegable", gssName));
				}

				String username = gssName.toString();

				return getPrincipal(username, gssCredential);
			}

		} catch (GSSException e) {
			throw new RuntimeException(e);
		}

		return null;
	}

	/**
	 * 
	 * @param gssCredential
	 * @throws RuntimeException
	 *             wraps GSSException and NamingException
	 * @return the retrieved principal
	 */
	public Principal authenticate(GSSCredential gssCredential) {

		try {

			GSSName gssName = gssCredential.getName();

			if (gssName != null) {
				String username = gssName.toString();

				return getPrincipal(username, gssCredential);
			}

		} catch (GSSException e) {
			throw new RuntimeException(e);
		}

		return null;
	}

	/*
	 * Must be accessed like this due to 
	 * http://www.mail-archive.com/users@tomcat.apache.org/msg98380.html
	 */
	@SuppressWarnings("unchecked")
	protected synchronized T lookupResource() throws NamingException {
		Context context = null;

		if(resource == null) {
			if (localResource) {
				context = ContextBindings.getClassLoader();
				context = (Context) context.lookup("comp/env");
			} else {
				StandardServer server = (StandardServer) ServerFactory.getServer();
				context = server.getGlobalNamingContext();
			}
			
			resource = (T) context.lookup(resourceName);
		}

		return resource;
	}

}
