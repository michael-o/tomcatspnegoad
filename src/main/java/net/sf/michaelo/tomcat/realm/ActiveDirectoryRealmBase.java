/*
 * Copyright 2013–2021 Michael Osipov
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

import org.apache.catalina.realm.RealmBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSName;

/**
 * Base realm which is able to retrieve principals from {@link GSSName GSS names} or fully
 * established {@link GSSContext GSS contexts}.
 */
public abstract class ActiveDirectoryRealmBase extends RealmBase {

	protected final Log logger = LogFactory.getLog(getClass());
	protected final StringManager sm = StringManager.getManager(getClass());

	/**
	 * @throws UnsupportedOperationException
	 *             always throws because not implemented
	 */
	@Override
	protected String getPassword(String username) {
		throw new UnsupportedOperationException(
				"getPassword(String) is not supported by this realm");
	}

	/**
	 * @throws UnsupportedOperationException
	 *             always throws because not implemented
	 */
	@Override
	protected Principal getPrincipal(String username) {
		throw new UnsupportedOperationException(
				"getPrincipal(String) is not supported by this realm");
	}

	@Override
	protected boolean hasRoleInternal(Principal principal, String role) {
		if (!(principal instanceof ActiveDirectoryPrincipal))
			return false;

		ActiveDirectoryPrincipal adp = (ActiveDirectoryPrincipal) principal;
		return adp.hasRole(role);
	}

	@Override
	public String[] getRoles(Principal principal) {
		if (principal instanceof ActiveDirectoryPrincipal) {
			return ((ActiveDirectoryPrincipal) principal).getRoles();
		}

		String className = principal.getClass().getName();
		throw new IllegalStateException(sm.getString("activeDirectoryRealmBase.cannotGetRoles",
				principal.getName(), className));
	}

}
