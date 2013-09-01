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
import net.sf.michaelo.tomcat.utils.Base64;

import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * A SPNEGO Authenticator which utilizes GSS-API to authenticate a client.
 * <p>
 * This authenticator has the following configuration options:
 * <ul>
 * <li>{@code loginEntryName}: Login entry name with a configured {@code Krb5LoginModule}.</li>
 * <li>{@code storeDelegatedCredential}: Store the client's/initiator's delegated credential in the
 * user principal (optional). Valid values are {@code true}, {@code false}. Default value is
 * {@code false}.</li>
 * </ul>
 * </p>
 *
 * @version $Id$
 */
/*
 * Error messages aren't reported correctly by the ErrorReportValve, see
 * http://www.mail-archive.com/users@tomcat.apache.org/msg98308.html Solution:
 * net.sf.michaelo.tomcat.extras.valves.EnhancedErrorReportValve
 */
public class SpnegoAuthenticator extends GssAwareAuthenticatorBase {

	protected static final String SPNEGO_METHOD = "SPNEGO";
	protected static final String NEGOTIATE_AUTH_SCHEME = "Negotiate";

	protected boolean storeDelegatedCredential;

	/**
	 * Sets the storage of client's/initiator's delegated credential in the user principal.
	 *
	 * @param storeDelegatedCredential
	 *            the store delegated credential indication
	 */
	public void setStoreDelegatedCredential(boolean storeDelegatedCredential) {
		this.storeDelegatedCredential = storeDelegatedCredential;
	}

	public boolean isStoreDelegatedCredential() {
		return storeDelegatedCredential;
	}

	@Override
	public String getInfo() {
		return "net.sf.michaelo.tomcat.authenticator.SpnegoAuthenticator/0.9";
	}

	protected void sendUnauthorizedHeader(Response response) throws IOException {
		response.setHeader("WWW-Authenticate", NEGOTIATE_AUTH_SCHEME);
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	}

	protected void sendUnauthorizedHeader(Response response, String message) throws IOException {
		response.setHeader("WWW-Authenticate", NEGOTIATE_AUTH_SCHEME);
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
	}

	@Override
	protected boolean authenticate(Request request, Response response, LoginConfig config)
			throws IOException {

		// HttpServletRequest request = req.getRequest();
		// HttpServletResponse response = resp.getResponse();

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

		String authorization = request.getHeader("Authorization");

		if (!StringUtils.startsWithIgnoreCase(authorization, NEGOTIATE_AUTH_SCHEME)) {
			sendUnauthorizedHeader(response);
			return false;
		}

		String authorizationValue = StringUtils
				.substringAfter(authorization, NEGOTIATE_AUTH_SCHEME);
		authorizationValue = StringUtils.trim(authorizationValue);

		if (StringUtils.isEmpty(authorizationValue)) {
			sendUnauthorizedHeader(response);
			return false;
		}

		byte[] outToken = null;
		byte[] inToken = null;

		if (logger.isDebugEnabled())
			logger.debug("Processing Negotiate authentication token " + authorizationValue);

		try {
			inToken = Base64.decode(authorizationValue);
		} catch (Exception e) {
			logger.error("The Negotiate authorization header value sent by the client was invalid: " + authorizationValue, e);

			sendUnauthorizedHeader(response, "The Negotiate authorization header value was invalid");
			return false;
		}

		LoginContext lc = null;
		GSSContext gssContext = null;

		try {
			try {
				lc = new LoginContext(getLoginEntryName());
				lc.login();
			} catch (LoginException e) {
				logger.error("Unable to login as the service principal", e);

				AuthenticationException ae = new AuthenticationException(
						"Unable to login as the service principal", e);
				sendException(request, response, ae);
				return false;
			}

			final GSSManager manager = GSSManager.getInstance();
			final PrivilegedExceptionAction<GSSCredential> serverCredentialAction = new PrivilegedExceptionAction<GSSCredential>() {
				@Override
				public GSSCredential run() throws GSSException {
					Oid spnegoMech = new Oid("1.3.6.1.5.5.2");
					return manager.createCredential(null, GSSCredential.DEFAULT_LIFETIME,
							spnegoMech, GSSCredential.ACCEPT_ONLY);
				}
			};

			try {
				gssContext = manager.createContext(Subject.doAs(lc.getSubject(),
						serverCredentialAction));
			} catch (PrivilegedActionException e) {
				logger.error("Unable to obtain the server credential", e.getException());

				AuthenticationException ae = new AuthenticationException(
						"Unable to obtain the server credential", e.getException());
				sendException(request, response, ae);
				return false;
			} catch (GSSException e) {
				logger.error("Failed to create a security context", e);

				AuthenticationException ae = new AuthenticationException(
						"Failed to create a security context", e);
				sendException(request, response, ae);
				return false;
			}

			try {
				outToken = gssContext.acceptSecContext(inToken, 0, inToken.length);

				/*
				 * This might now work anyway because Tomcat does not support connection-level
				 * authentication. One actually have to cache the GSSContext in the HTTP session.
				 */
				if (!gssContext.isEstablished()) {
					if (logger.isDebugEnabled())
						logger.debug("Security context not yet established, continuing");

					response.setHeader("WWW-Authenticate",
							NEGOTIATE_AUTH_SCHEME + " " + Base64.encode(outToken));
					response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
					return false;
				} else {
					GssAwareRealmBase<?> realm = (GssAwareRealmBase<?>) context.getRealm();
					GSSName srcName = gssContext.getSrcName();
					Oid negotiatedMech = gssContext.getMech();

					GSSCredential delegatedCredential = null;
					if (storeDelegatedCredential) {
						if (gssContext.getCredDelegState()) {
							delegatedCredential = gssContext.getDelegCred();
						} else
							logger.debug(String.format("Credential of '%s' is not delegable though storing was requested", srcName));
					}

					principal = realm.authenticate(srcName, negotiatedMech, delegatedCredential);
				}

			} catch (GSSException e) {
				logger.warn(
						"Failed to accept security context with client-supplied service ticket: "
								+ authorizationValue, e);

				// TODO Maybe a 401 is better suited here?
				AuthenticationException ae = new AuthenticationException(
						"Failed to accept security context with client-supplied service ticket", e);
				sendException(request, response, ae);
				return false;
			} catch (RuntimeException e) {
				// TODO No logging necessary, it happens already in the realm. Maybe move to here.
				AuthenticationException ae = new AuthenticationException(
						"Unable to perform user principal search", e);
				sendException(request, response, ae);
				return false;
			}

		} finally {
			if (gssContext != null) {
				try {
					gssContext.dispose();
				} catch (GSSException e) {
					// Ignore
				}
			}
			if (lc != null) {
				try {
					lc.logout();
				} catch (LoginException e) {
					// Ignore
				}
			}
		}

		if (principal != null) {
			register(request, response, principal, SPNEGO_METHOD, principal.getName(), null);
			if (ArrayUtils.isNotEmpty(outToken)) {
				// Send response token if there is one
				response.setHeader("WWW-Authenticate",
						NEGOTIATE_AUTH_SCHEME + " " + Base64.encode(outToken));
				// Connection must be closed due to
				// https://issues.apache.org/bugzilla/show_bug.cgi?id=54076
				response.addHeader("Connection", "close");
			}
			return true;
		}

		sendUnauthorizedHeader(response);
		return false;
	}

}
