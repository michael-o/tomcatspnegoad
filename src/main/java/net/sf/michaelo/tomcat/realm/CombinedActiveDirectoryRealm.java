/*
 * Copyright 2013–2019 Michael Osipov
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

import org.apache.catalina.realm.CombinedRealm;

/**
 * A combined realm which wraps multiple {@link ActiveDirectoryRealm ActiveDirectoryRealms}
 * together. It iterates over all realms and tries to authenticate a user. The first non-null
 * principal is returned.
 * <p>
 * The usage is the same as with the {@link CombinedRealm} but the sub-realms must be
 * {@code ActiveDirectoryRealms}. Example configuration:
 *
 * <pre>
 *  &lt;Realm className="net.sf.michaelo.tomcat.realm.CombinedActiveDirectoryRealm"&gt;
 *    &lt;Realm className="net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm"
 *      dirContextSourceName="my-active-directory-forest1" /&gt;
 *    &lt;Realm className="net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm"
 *      dirContextSourceName="my-active-directory-forest2" /&gt;
 *  &lt;/Realm&gt;
 * </pre>
 * <p>
 * <strong>Acknowledgement:</strong> Portions of this code were copied from the original
 * {@code CombinedRealm} and modified to the needs of the {@code ActiveDirectoryRealm}.
 *
 * @see ActiveDirectoryRealm
 * @version $Id$
 */
public class CombinedActiveDirectoryRealm extends CombinedRealm {

	/**
	 * Descriptive information about this Realm implementation.
	 */
	protected static final String name = "CombinedActiveDirectoryRealm";

	@Override
	protected String getName() {
		return name;
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
