/*
 * Copyright 2013–2024 Michael Osipov
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
import java.security.cert.X509Certificate;

import org.apache.catalina.realm.RealmBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSName;

/**
 * Base Active Directory realm which is able to retrieve principals for {@link GSSName GSS names},
 * fully established {@link GSSContext security contexts} or {@link X509Certificate TLS client certificates}.
 */
public abstract class ActiveDirectoryRealmBase extends RealmBase {

	protected final Log logger = LogFactory.getLog(getClass());
	protected final StringManager sm = StringManager.getManager(getClass());

	/**
	 * @return Always {@code null} as this realm has no way of obtaining this
	 * information.
	 */
	@Override
	protected String getPassword(String username) {
		// Always return null
		return null;
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
