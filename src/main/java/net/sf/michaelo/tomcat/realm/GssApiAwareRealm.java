/*
 * Copyright 2013 Michael Osipov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

/**
 * Base realm which is able to retrieve principals from GSS contexts and credentials.
 *
 * @version $Id$
 */
public abstract class GssApiAwareRealm<T> extends RealmBase {

	private static final Log logger = LogFactory.getLog(GssApiAwareRealm.class);

	protected boolean localResource;
	protected String resourceName;

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
	 * Authenticates a user from the given GSS context and eventually store his/her GSS credential.
	 *
	 * @param gssContext
	 *            GSS context established with the user
	 * @param storeDelegatedCredential
	 *            whether to store user's delegated credential
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
						logger.debug(String.format("Credential of '%s' is not delegable though storing was requested", gssName));
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
	 * Authenticates a user from the given GSS credential and stores it.
	 *
	 * @param gssCredential
	 *            user's GSS credential
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
	protected T lookupResource() throws NamingException {
		Context context = null;

		if (localResource) {
			context = ContextBindings.getClassLoader();
			context = (Context) context.lookup("comp/env");
		} else {
			StandardServer server = (StandardServer) ServerFactory.getServer();
			context = server.getGlobalNamingContext();
		}

		return (T) context.lookup(resourceName);
	}

}
