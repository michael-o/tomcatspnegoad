/*
 * Copyright 2013–2016 Michael Osipov
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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.naming.NamingException;

import org.apache.catalina.Group;
import org.apache.catalina.Role;
import org.apache.catalina.User;
import org.apache.catalina.UserDatabase;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.UserDatabaseRealm;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

/**
 * A GSS-aware {@link UserDatabaseRealm}.
 *
 * @version $Id$
 */
public class GSSUserDatabaseRealm extends GSSRealmBase<UserDatabase> {

	@Override
	public String getInfo() {
		return "net.sf.michaelo.realm.GSSUserDatabaseRealm/2.0";
	}

	@Override
	protected String getName() {
		return "GSSUserDatabaseRealm";
	}

	@Override
	public Principal authenticate(GSSName gssName) {
		if(gssName == null)
			throw new NullPointerException("gssName cannot be null");

		UserDatabase database = null;

		try {
			database = lookupResource();
		} catch (NamingException e) {
			logger.error(sm.getString("userDatabaseRealm.lookupFailed", resourceName), e);

			return null;
		}

		String username = gssName.toString();
		User user = database.findUser(username);
		if (user == null) {
			return new GenericPrincipal(this, username, null);
		}

		List<String> roles = new ArrayList<String>();
		Iterator<?> uroles = user.getRoles();
		while (uroles.hasNext()) {
			Role role = (Role) uroles.next();
			roles.add(role.getName());
		}
		Iterator<?> groups = user.getGroups();
		while (groups.hasNext()) {
			Group group = (Group) groups.next();
			uroles = group.getRoles();
			while (uroles.hasNext()) {
				Role role = (Role) uroles.next();
				roles.add(role.getName());
			}
		}

		return new GenericPrincipal(this, username, null, roles, user);
	}

	@Override
	public Principal authenticate(GSSContext gssContext) {
		if(gssContext == null)
			throw new NullPointerException("gssContext cannot be null");

		if(!gssContext.isEstablished())
			throw new IllegalStateException("gssContext is not fully established");

		try {
			GSSName gssName = gssContext.getSrcName();
			return authenticate(gssName);
		} catch (GSSException e) {
			logger.error(sm.getString("realm.inquireFailed"), e);

			return null;
		}
	}

	public boolean hasRole(Principal principal, String role) {
		if (principal instanceof GenericPrincipal) {
			GenericPrincipal gp = (GenericPrincipal) principal;
			if (gp.getUserPrincipal() instanceof User) {
				principal = gp.getUserPrincipal();
			}
		}
		if (!(principal instanceof User)) {
			// Play nice with SSO and mixed Realms
			return super.hasRole(principal, role);
		}
		if ("*".equals(role)) {
			return true;
		} else if (role == null) {
			return false;
		}
		User user = (User) principal;

		UserDatabase database;
		try {
			database = lookupResource();
		} catch (NamingException e) {
			logger.error(sm.getString("userDatabaseRealm.lookupFailed", resourceName), e);

			return false;
		}

		Role dbrole = database.findRole(role);
		if (dbrole == null) {
			return false;
		}
		if (user.isInRole(dbrole)) {
			return true;
		}
		Iterator<?> groups = user.getGroups();
		while (groups.hasNext()) {
			Group group = (Group) groups.next();
			if (group.isInRole(dbrole)) {
				return true;
			}
		}
		return false;
	}

}
