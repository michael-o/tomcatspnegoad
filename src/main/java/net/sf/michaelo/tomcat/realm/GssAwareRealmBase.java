/*
 * Copyright 2013–2015 Michael Osipov
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
import org.apache.catalina.util.StringManager;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.naming.ContextBindings;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * Base realm which is able to retrieve principals from {@link GSSName GSS names}.
 *
 * @version $Id$
 */
public abstract class GssAwareRealmBase<T> extends RealmBase {

	protected final Log logger = LogFactory.getLog(getClass());
	protected final StringManager sm = StringManager.getManager(getClass().getPackage().getName());

	protected boolean localResource;
	protected String resourceName;

	public void setLocalResource(boolean localResource) {
		this.localResource = localResource;
	}

	public void setResourceName(String resourceName) {
		this.resourceName = resourceName;
	}

	@Override
	protected String getPassword(String username) {
		throw new UnsupportedOperationException("This method is not supported by this realm");
	}

	@Override
	protected Principal getPrincipal(String username) {
		throw new UnsupportedOperationException("This method is not supported by this realm");
	}

	/**
	 * Authenticates a user from the given GSS name and eventually store his/her GSS credential.
	 *
	 * @param gssName
	 *            the GSS name of the context initiator (client)
	 * @param mech
	 *            the used (negotiated) GSS mechanism of this context
	 * @param delegatedCredential
	 *            an eventually available delegated GSS credential
	 * @return the retrieved principal
	 * @throws RuntimeException
	 *             wraps {@link GSSException} and {@link NamingException}
	 */
	abstract public Principal authenticate(GSSName gssName, Oid mech,
			GSSCredential delegatedCredential);

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
