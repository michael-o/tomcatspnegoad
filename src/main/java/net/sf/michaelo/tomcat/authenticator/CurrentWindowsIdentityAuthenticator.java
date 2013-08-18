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
package net.sf.michaelo.tomcat.authenticator;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletResponse;

import net.sf.michaelo.tomcat.realm.GssAwareRealmBase;

import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * Windows Identitiy Authenticator which uses GSS-API to retrieve to currently logged in user.
 * <p>
 * This authenticator has the following configuration options:
 * <ul>
 * <li>{@code loginEntryName}: Login entry name with a configured {@code Krb5LoginModule}.</li>
 * </ul>
 * </p>
 *
 * @version $Id$
 */
public class CurrentWindowsIdentityAuthenticator extends GssAwareAuthenticatorBase {

	protected static final String CURRENT_WINDOWS_IDENTITY_METHOD = "CURRENT_WINDOWS_IDENTITY";

	@Override
	public String getInfo() {
		return "net.sf.michaelo.tomcat.authenticator.CurrentWindowsIdentityAuthenticator/0.9";
	}

	@Override
	protected boolean authenticate(Request request, Response response, LoginConfig config)
			throws IOException {

		Principal principal = request.getUserPrincipal();
		// String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
		if (principal != null) {
			if (logger.isDebugEnabled())
				logger.debug(String.format("Already authenticated '%s'", principal));
			String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
			if (ssoId != null)
				associate(ssoId, request.getSessionInternal(true));
			return true;
		}

		// NOTE: We don't try to reauthenticate using any existing SSO session,
		// because that will only work if the original authentication was
		// BASIC or FORM, which are less secure than the DIGEST auth-type
		// specified for this webapp

		/*
		if (ssoId != null) {
			if (logger.isDebugEnabled())
				logger.debug(String.format("SSO Id %s set; attempting reauthentication", ssoId));

			if (reauthenticateFromSSO(ssoId, request))
				return true;
		}
		*/

		LoginContext lc = null;

		try {
			try {
				lc = new LoginContext(getLoginEntryName());
				lc.login();
			} catch (LoginException e) {
				logger.error("Unable to login as the user principal", e);

				AuthenticationException ae = new AuthenticationException(
						"Unable to login as the user principal", e);
				sendException(request, response, ae);
				return false;
			}

			final GSSManager manager = GSSManager.getInstance();
			final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
				@Override
				public GSSCredential run() throws GSSException {
					Oid krb5Mech = new Oid("1.2.840.113554.1.2.2");
					return manager.createCredential(null, GSSCredential.DEFAULT_LIFETIME, krb5Mech,
							GSSCredential.INITIATE_ONLY);
				}
			};

			GSSCredential gssCredential = null;

			try {
				gssCredential = Subject.doAs(lc.getSubject(), action);
			} catch (PrivilegedActionException e) {
				logger.error("Unable to obtain the user credential", e.getException());

				AuthenticationException ae = new AuthenticationException(
						"Unable to obtain the user credential", e.getException());
				sendException(request, response, ae);
				return false;
			}

			try {
				GssAwareRealmBase<?> realm = (GssAwareRealmBase<?>) context.getRealm();
				GSSName srcName = gssCredential.getName();
				Oid krb5Mech = new Oid("1.2.840.113554.1.2.2");

				principal = realm.authenticate(srcName, krb5Mech, gssCredential);
			} catch (GSSException e) {
				logger.warn(
						"Failed to retrive GSSName form GSSCredential of the user", e);

				// TODO Maybe a 401 is better suited here?
				AuthenticationException ae = new AuthenticationException(
						"Failed to retrive GSSName form GSSCredential of the user", e);
				sendException(request, response, ae);
				return false;
			} catch (RuntimeException e) {
				// Logging happens already in the Realm
				AuthenticationException ae = new AuthenticationException(
						"Unable to perform user principal search", e);
				sendException(request, response, ae);
				return false;
			}

		} finally {
			if (lc != null) {
				try {
					lc.logout();
				} catch (LoginException e) {
					// Ignore
				}
			}
		}

		if (principal != null) {
			register(request, response, principal, CURRENT_WINDOWS_IDENTITY_METHOD,
					principal.getName(), null);
			return true;
		}

		response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		return false;
	}

}
