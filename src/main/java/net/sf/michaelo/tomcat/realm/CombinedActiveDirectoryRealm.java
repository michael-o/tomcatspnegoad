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
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.management.ObjectName;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Realm;
import org.apache.catalina.realm.CombinedRealm;
import org.apache.catalina.realm.RealmBase;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;

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
public class CombinedActiveDirectoryRealm extends GSSRealmBase {

	/**
	 * The list of Realms contained by this Realm.
	 */
	protected List<ActiveDirectoryRealm> realms = new LinkedList<>();

	/**
	 * Descriptive information about this Realm implementation.
	 */
	protected static final String name = "CombinedActiveDirectoryRealm";

	@Override
	protected String getName() {
		return name;
	}

	/**
	 * @see CombinedRealm#addRealm(Realm)
	 */
	public void addRealm(Realm theRealm) {
		realms.add((ActiveDirectoryRealm) theRealm);
	}

	/**
	 * @see CombinedRealm#getRealms()
	 */
	public ObjectName[] getRealms() {
		ObjectName[] result = new ObjectName[realms.size()];
		for (Realm realm : realms) {
			if (realm instanceof RealmBase)
				result[realms.indexOf(realm)] = ((RealmBase) realm).getObjectName();
		}
		return result;
	}

	/**
	 * @see CombinedRealm#getNestedRealms()
	 */
	public Realm[] getNestedRealms() {
		return realms.toArray(new Realm[0]);
	}

	/**
	 * @see CombinedRealm#setContainer(Container)
	 */
	@Override
	public void setContainer(Container container) {
		for (Realm realm : realms) {
			// Set the realmPath for JMX naming
			if (realm instanceof RealmBase) {
				((RealmBase) realm).setRealmPath(getRealmPath() + "/realm" + realms.indexOf(realm));
			}

			// Set the container for sub-realms. Mainly so logging works.
			realm.setContainer(container);
		}
		super.setContainer(container);
	}

	/**
	 * @see CombinedRealm#startInternal()
	 */
	@Override
	protected void startInternal() throws LifecycleException {
		// Start 'sub-realms' then this one
		Iterator<ActiveDirectoryRealm> iter = realms.iterator();

		while (iter.hasNext()) {
			Realm realm = iter.next();
			if (realm instanceof Lifecycle) {
				try {
					((Lifecycle) realm).start();
				} catch (LifecycleException e) {
					// If realm doesn't start can't authenticate against it
					iter.remove();
					logger.error(sm.getString("combinedActiveDirectoryRealm.realmStartFailed",
							realm.getClass().getName()), e);
				}
			}
		}
		super.startInternal();
	}

	/**
	 * @see CombinedRealm#stopInternal()
	 */
	@Override
	protected void stopInternal() throws LifecycleException {
		// Stop this realm, then the sub-realms (reverse order to start)
		super.stopInternal();
		for (Realm realm : realms) {
			if (realm instanceof Lifecycle) {
				((Lifecycle) realm).stop();
			}
		}
	}

	/**
	 * @see CombinedRealm#destroyInternal()
	 */
	@Override
	protected void destroyInternal() throws LifecycleException {
		for (Realm realm : realms) {
			if (realm instanceof Lifecycle) {
				((Lifecycle) realm).destroy();
			}
		}
		super.destroyInternal();
	}

	/**
	 * @see CombinedRealm#backgroundProcess()
	 */
	@Override
	public void backgroundProcess() {
		super.backgroundProcess();

		for (Realm r : realms) {
			r.backgroundProcess();
		}
	}

	@Override
	public Principal authenticate(GSSName gssName, GSSCredential gssCredential) {
		ActiveDirectoryPrincipal principal = null;

		for (ActiveDirectoryRealm realm : realms) {
			principal = (ActiveDirectoryPrincipal) realm.authenticate(gssName, gssCredential);

			if (principal != null)
				break;
		}

		return principal;
	}

	@Override
	public Principal authenticate(GSSContext gssContext, boolean storeCreds) {
		ActiveDirectoryPrincipal principal = null;

		for (ActiveDirectoryRealm realm : realms) {
			principal = (ActiveDirectoryPrincipal) realm.authenticate(gssContext, storeCreds);

			if (principal != null)
				break;
		}

		return principal;
	}

	@Override
	protected boolean hasRoleInternal(Principal principal, String role) {
		if (!(principal instanceof ActiveDirectoryPrincipal))
			return false;

		ActiveDirectoryPrincipal adp = (ActiveDirectoryPrincipal) principal;
		return adp.hasRole(role);
	}

	/**
	 * @throws UnsupportedOperationException
	 *             always throws because not implemented
	 */
	@Override
	protected Principal getPrincipal(GSSName gssName, GSSCredential gssCredential) {
		throw new UnsupportedOperationException(
				"getPrincipal(GSSName, GSSCredential) is currently not supported by this realm");
	}

	@Override
	public boolean isAvailable() {
		for (Realm realm : realms) {
			if (!realm.isAvailable()) {
				return false;
			}
		}
		return true;
	}

}
