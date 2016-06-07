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
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.management.ObjectName;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Realm;
import org.apache.catalina.realm.CombinedRealm;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.ietf.jgss.GSSContext;
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
 *      resourceName="my-active-directory1" /&gt;
 *    &lt;Realm className="net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm"
 *      resourceName="my-active-directory2" /&gt;
 *  &lt;/Realm&gt;
 * </pre>
 * <p>
 * <strong>Acknowledgement:</strong> Portions of this code were copied from the original
 * {@code CombinedRealm} and modified to the needs of the {@code ActiveDirectoryRealm}.
 *
 * @see ActiveDirectoryRealm
 * @version $Id$
 */
public class CombinedActiveDirectoryRealm extends GSSRealmBase<Object> {

	private static Log log = LogFactory.getLog(CombinedActiveDirectoryRealm.class);

	/**
	 * The list of Realms contained by this Realm.
	 */
	protected List<ActiveDirectoryRealm> realms = new LinkedList<ActiveDirectoryRealm>();

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
		for (ActiveDirectoryRealm realm : realms) {
			result[realms.indexOf(realm)] = realm.getObjectName();
		}
		return result;
	}

	/**
	 * @see CombinedRealm#setContainer(Container)
	 */
	@Override
	public void setContainer(Container container) {
		for (ActiveDirectoryRealm realm : realms) {
			// Set the realmPath for JMX naming
			realm.setRealmPath(getRealmPath() + "/realm" + realms.indexOf(realm));

			// Set the container for sub-realms. Mainly so logging works.
			realm.setContainer(container);
		}
		super.setContainer(container);
	}

	/**
	 * @see CombinedRealm#start()
	 */
	@Override
	public void start() throws LifecycleException {
		// Start 'sub-realms' then this one
		Iterator<ActiveDirectoryRealm> iter = realms.iterator();

		while (iter.hasNext()) {
			ActiveDirectoryRealm realm = iter.next();
			try {
				realm.start();
			} catch (LifecycleException e) {
				// If realm doesn't start can't authenticate against it
				iter.remove();
				log.error(sm.getString("combinedActiveDirectoryRealm.realmStartFailed", realm.getInfo()), e);
			}
		}
		super.start();
	}

	/**
	 * @see CombinedRealm#stop()
	 */
	@Override
	public void stop() throws LifecycleException {
		// Stop this realm, then the sub-realms (reverse order to start)
		super.stop();
		for (ActiveDirectoryRealm realm : realms) {
			realm.stop();
		}
	}

	/**
	 * @see CombinedRealm#backgroundProcess()
	 */
	@Override
	public void backgroundProcess() {
		super.backgroundProcess();

		for (ActiveDirectoryRealm r : realms) {
			r.backgroundProcess();
		}
	}

	@Override
	public String getInfo() {
		return "net.sf.michaelo.tomcat.realm.CombinedActiveDirectoryRealm/2.0";
	}

	@Override
	protected String getName() {
		return "CombinedActiveDirectoryRealm";
	}

	@Override
	public Principal authenticate(GSSName gssName) {
		ActiveDirectoryPrincipal principal = null;

		for (ActiveDirectoryRealm realm : realms) {
			principal = (ActiveDirectoryPrincipal) realm.authenticate(gssName);

			if (principal != null)
				break;
		}

		return principal;
	}

	@Override
	public Principal authenticate(GSSContext gssContext) {
		ActiveDirectoryPrincipal principal = null;

		for (ActiveDirectoryRealm realm : realms) {
			principal = (ActiveDirectoryPrincipal) realm.authenticate(gssContext);

			if (principal != null)
				break;
		}

		return principal;
	}

	@Override
	public boolean hasRole(Principal principal, String role) {
		if (principal == null || role == null || !(principal instanceof ActiveDirectoryPrincipal))
			return false;

		ActiveDirectoryPrincipal adp = (ActiveDirectoryPrincipal) principal;

		boolean result;
		if (container instanceof Context) {
			Context context = (Context) container;
			result = adp.hasRole(context.findRoleMapping(role));
		} else
			result = adp.hasRole(role);

		if (logger.isDebugEnabled()) {
			if (result)
				logger.debug(sm.getString("activeDirectoryRealm.hasRole", principal, role));
			else
				logger.debug(sm.getString("activeDirectoryRealm.hasNotRole", principal, role));
		}

		return result;
	}

}
