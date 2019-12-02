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
package net.sf.michaelo.tomcat.authenticator;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.GSSRealm;
import org.apache.catalina.Realm;
import org.apache.catalina.connector.Request;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

/**
 * A Windows Identity Authenticator which uses GSS-API to retrieve to currently logged in user.
 *
 * @version $Id$
 */
public class CurrentWindowsIdentityAuthenticator extends GSSAuthenticatorBase {

	protected static final String CURRENT_WINDOWS_IDENTITY_METHOD = "CURRENT_WINDOWS_IDENTITY";
	protected static final String CURRENT_WINDOWS_IDENTITY_AUTH_SCHEME = "CWI";

	@Override
	protected boolean doAuthenticate(Request request, HttpServletResponse response)
			throws IOException {

		if (checkForCachedAuthentication(request, response, true)) {
			return true;
		}

		LoginContext lc = null;

		try {
			try {
				lc = new LoginContext(getLoginEntryName());
				lc.login();
			} catch (LoginException e) {
				logger.error(sm.getString("cwiAuthenticator.obtainFailed"), e);

				sendUnauthorized(request, response, CURRENT_WINDOWS_IDENTITY_AUTH_SCHEME,
						"cwiAuthenticator.obtainFailed");
				return false;
			}

			final GSSManager manager = GSSManager.getInstance();
			final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
				@Override
				public GSSCredential run() throws GSSException {
					return manager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME,
							KRB5_MECHANISM, GSSCredential.INITIATE_ONLY);
				}
			};

			GSSCredential gssCredential = null;

			try {
				gssCredential = Subject.doAs(lc.getSubject(), action);
			} catch (PrivilegedActionException e) {
				logger.error(sm.getString("cwiAuthenticator.obtainFailed"), e.getException());

				sendUnauthorized(request, response, CURRENT_WINDOWS_IDENTITY_AUTH_SCHEME,
						"cwiAuthenticator.obtainFailed");
				return false;
			}

			try {
				GSSRealm realm = (GSSRealm) context.getRealm();
				GSSName gssName = gssCredential.getName();

				Principal principal = realm.authenticate(gssName,
						isStoreDelegatedCredential() ? gssCredential : null);

				if (principal != null) {
					register(request, response, principal, getAuthMethod(), principal.getName(),
							null);
					return true;
				} else {
					sendUnauthorized(request, response, CURRENT_WINDOWS_IDENTITY_AUTH_SCHEME,
							"gssAuthenticatorBase.userNotFound", gssName);
					return false;
				}
			} catch (GSSException e) {
				logger.error(sm.getString("gssAuthenticatorBase.inquireNameFailed"), e);

				sendInternalServerError(request, response, "gssAuthenticatorBase.inquireNameFailed");
				return false;
			}
		} finally {
			if (lc != null) {
				try {
					lc.logout();
				} catch (LoginException e) {
					; // Ignore
				}
			}
		}
	}

	@Override
	protected String getAuthMethod() {
		return CURRENT_WINDOWS_IDENTITY_METHOD;
	}

}
