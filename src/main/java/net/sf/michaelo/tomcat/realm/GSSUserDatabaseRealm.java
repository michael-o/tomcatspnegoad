/*
 * Copyright 2013–2017 Michael Osipov
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

import org.apache.catalina.realm.UserDatabaseRealm;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

/**
 * A GSS-aware {@link UserDatabaseRealm}.
 *
 * @version $Id$
 */
public class GSSUserDatabaseRealm extends UserDatabaseRealm implements GSSRealm {

	protected final Log logger = LogFactory.getLog(getClass());
	protected final StringManager sm = StringManager.getManager(getClass().getPackage().getName());

	/**
	 * Descriptive information about this Realm implementation.
	 */
	protected static final String name = "GSSUserDatabaseRealm";

	@Override
	protected String getName() {
		return name;
	}

	public Principal authenticate(GSSName gssName, GSSCredential gssCredential) {
		return getPrincipal(String.valueOf(gssName), gssCredential);
	}

	@Override
	public Principal authenticate(GSSContext gssContext, boolean storeCred) {
		if (gssContext.isEstablished()) {
			GSSName gssName = null;
			try {
				gssName = gssContext.getSrcName();
			} catch (GSSException e) {
				logger.error(sm.getString("activeDirectoryRealm.gssNameFailed"), e);
			}

			if (gssName != null) {
				GSSCredential gssCredential = null;
				if (storeCred) {
					if (gssContext.getCredDelegState()) {
						try {
							gssCredential = gssContext.getDelegCred();
						} catch (GSSException e) {
							logger.warn(sm.getString(
									"activeDirectoryRealm.delegatedCredentialFailed", gssName), e);
						}
					} else {
						if (logger.isDebugEnabled())
							logger.debug(sm.getString(
									"activeDirectoryRealm.credentialNotDelegable", gssName));
					}
				}

				return getPrincipal(String.valueOf(gssName), gssCredential);
			}
		} else
			logger.error(sm.getString("activeDirectoryRealm.securityContextNotEstablished"));

		return null;
	}

}
