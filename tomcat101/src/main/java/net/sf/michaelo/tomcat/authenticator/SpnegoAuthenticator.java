/*
 * Copyright 2013–2023 Michael Osipov
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

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.catalina.Realm;
import org.apache.catalina.connector.Request;
import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

/**
 * A SPNEGO Authenticator which utilizes GSS-API to authenticate a client.
 */
public class SpnegoAuthenticator extends GSSAuthenticatorBase {

	protected static final String SPNEGO_METHOD = "SPNEGO";
	protected static final String SPNEGO_AUTH_SCHEME = "Negotiate";

	private static final byte[] NTLM_TYPE1_MESSAGE_START = { (byte) 'N', (byte) 'T', (byte) 'L',
			(byte) 'M', (byte) 'S', (byte) 'S', (byte) 'P', (byte) '\0', (byte) 0x01, (byte) 0x00,
			(byte) 0x00, (byte) 0x00 };

	@Override
	protected boolean doAuthenticate(Request request, HttpServletResponse response)
			throws IOException {

		if (checkForCachedAuthentication(request, response, true)) {
			return true;
		}

		String authorization = request.getHeader("Authorization");

		if (!StringUtils.startsWithIgnoreCase(authorization, SPNEGO_AUTH_SCHEME)) {
			sendUnauthorized(request, response, SPNEGO_AUTH_SCHEME);
			return false;
		}

		String authorizationValue = StringUtils.substring(authorization,
				SPNEGO_AUTH_SCHEME.length() + 1);

		if (StringUtils.isEmpty(authorizationValue)) {
			sendUnauthorized(request, response, SPNEGO_AUTH_SCHEME);
			return false;
		}

		byte[] outToken = null;
		byte[] inToken = null;

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("spnegoAuthenticator.processingToken", authorizationValue));

		try {
			inToken = Base64.decodeBase64(authorizationValue);
		} catch (Exception e) {
			logger.warn(sm.getString("spnegoAuthenticator.incorrectlyEncodedToken",
					authorizationValue), e);

			sendUnauthorized(request, response, SPNEGO_AUTH_SCHEME,
					"spnegoAuthenticator.incorrectlyEncodedToken.responseMessage");
			return false;
		}

		if (inToken.length >= NTLM_TYPE1_MESSAGE_START.length) {
			boolean ntlmDetected = false;
			for (int i = 0; i < NTLM_TYPE1_MESSAGE_START.length; i++) {
				ntlmDetected = inToken[i] == NTLM_TYPE1_MESSAGE_START[i];

				if (!ntlmDetected)
					break;
			}

			if (ntlmDetected) {
				logger.warn(sm.getString("spnegoAuthenticator.ntlmNotSupported"));

				sendUnauthorized(request, response, SPNEGO_AUTH_SCHEME,
						"spnegoAuthenticator.ntlmNotSupported.responseMessage");
				return false;
			}
		}

		LoginContext lc = null;
		GSSContext gssContext = null;
		Principal principal = null;

		try {
			try {
				lc = new LoginContext(getLoginEntryName());
				lc.login();
			} catch (LoginException e) {
				logger.error(sm.getString("spnegoAuthenticator.obtainFailed"), e);

				sendInternalServerError(request, response, "spnegoAuthenticator.obtainFailed");
				return false;
			}

			final GSSManager manager = GSSManager.getInstance();
			final PrivilegedExceptionAction<GSSCredential> action = () -> manager.createCredential(null,
					GSSCredential.INDEFINITE_LIFETIME, SPNEGO_MECHANISM, GSSCredential.ACCEPT_ONLY);

			try {
				gssContext = manager.createContext(Subject.doAs(lc.getSubject(), action));
			} catch (PrivilegedActionException e) {
				logger.error(sm.getString("spnegoAuthenticator.obtainFailed"), e.getException());

				sendInternalServerError(request, response, "spnegoAuthenticator.obtainFailed");
				return false;
			} catch (GSSException e) {
				logger.error(sm.getString("spnegoAuthenticator.createContextFailed"), e);

				sendInternalServerError(request, response,
						"spnegoAuthenticator.createContextFailed");
				return false;
			}

			try {
				outToken = gssContext.acceptSecContext(inToken, 0, inToken.length);
			} catch (GSSException e) {
				logger.warn(sm.getString("spnegoAuthenticator.invalidToken", authorizationValue), e);

				sendUnauthorized(request, response, SPNEGO_AUTH_SCHEME,
						"spnegoAuthenticator.invalidToken.responseMessage");
				return false;
			}

			try {
				if (gssContext.isEstablished()) {
					if (logger.isDebugEnabled())
						logger.debug(sm.getString("spnegoAuthenticator.contextSuccessfullyEstablished"));

					Realm realm = context.getRealm();
					principal = realm.authenticate(gssContext, isStoreDelegatedCredential());

					if (principal == null) {
						GSSName srcName = gssContext.getSrcName();
						sendUnauthorized(request, response, SPNEGO_AUTH_SCHEME,
								"gssAuthenticatorBase.userNotFound", srcName);
						return false;
					}
				} else {
					logger.error(sm.getString("spnegoAuthenticator.continueContextNotSupported"));

					sendInternalServerError(request, response,
							"spnegoAuthenticator.continueContextNotSupported.responseMessage");
					return false;
				}

			} catch (GSSException e) {
				logger.error(sm.getString("gssAuthenticatorBase.inquireNameFailed"), e);

				sendInternalServerError(request, response, "gssAuthenticatorBase.inquireNameFailed");
				return false;
			}

		} finally {
			if (gssContext != null) {
				try {
					gssContext.dispose();
				} catch (GSSException e) {
					; // Ignore
				}
			}
			if (lc != null) {
				try {
					lc.logout();
				} catch (LoginException e) {
					; // Ignore
				}
			}
		}

		register(request, response, principal, SPNEGO_METHOD, principal.getName(), null);

		if (outToken != null) {
			String authenticationValue = Base64.encodeBase64String(outToken);
			if (logger.isDebugEnabled())
				logger.debug(sm.getString("spnegoAuthenticator.respondingWithToken", authenticationValue));

			response.setHeader(AUTH_HEADER_NAME, SPNEGO_AUTH_SCHEME + " " + authenticationValue);
		}

		return true;
	}

	@Override
	protected boolean isPreemptiveAuthPossible(Request request) {
		String authorization = request.getHeader("Authorization");

		return StringUtils.startsWithIgnoreCase(authorization, SPNEGO_AUTH_SCHEME);
	}

	@Override
	protected String getAuthMethod() {
		return SPNEGO_METHOD;
	}

}
