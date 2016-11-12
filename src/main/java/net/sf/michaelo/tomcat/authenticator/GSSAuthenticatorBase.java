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
package net.sf.michaelo.tomcat.authenticator;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.util.StringManager;
import org.apache.commons.lang3.StringUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

/**
 * Base implementation for GSS-based authenticators which holds common configuration information.
 *
 * @version $Id$
 */
abstract class GSSAuthenticatorBase extends AuthenticatorBase {

	protected final Log logger = LogFactory.getLog(getClass());
	protected final StringManager sm = StringManager.getManager(getClass().getPackage().getName());

	protected final static Oid KRB5_MECHANISM;
	protected final static Oid SPNEGO_MECHANISM;

	static {
		try {
			KRB5_MECHANISM = new Oid("1.2.840.113554.1.2.2");
		} catch (GSSException e) {
			throw new IllegalStateException("Failed to create OID for Kerberos 5 mechanism");
		}

		try {
			SPNEGO_MECHANISM = new Oid("1.3.6.1.5.5.2");
		} catch (GSSException e) {
			throw new IllegalStateException("Failed to create OID for SPNEGO mechanism");
		}
	}

	private String loginEntryName;
	private boolean omitErrorMessages;
	private boolean errorMessagesAsHeaders;

	/**
	 * Sets the login entry name which establishes the security context.
	 *
	 * @param loginEntryName
	 *            the login entry name
	 */
	public void setLoginEntryName(String loginEntryName) {
		this.loginEntryName = loginEntryName;
	}

	/**
	 * Returns the configured login entry name.
	 *
	 * @return the login entry name
	 */
	public String getLoginEntryName() {
		return loginEntryName;
	}

	/**
	 * Indicates whether error messages are responded to the client.
	 *
	 * @return indicator for error message omission
	 */
	public boolean isOmitErrorMessages() {
		return omitErrorMessages;
	}

	/**
	 * Sets whether error messages are responded to the client.
	 *
	 * @param omitErrorMessages
	 *            indicator to error omit messages
	 */
	public void setOmitErrorMessages(boolean omitErrorMessages) {
		this.omitErrorMessages = omitErrorMessages;
	}

	/**
	 * Indicates whether error messages will be responded as headers.
	 *
	 * @return indicates whether error messages will be responded as headers
	 */
	public boolean isErrorMessagesAsHeaders() {
		return errorMessagesAsHeaders;
	}

	/**
	 * Sets whether error messages will be returned as headers.
	 *
	 * <p>
	 * It is not always desired or necessary to produce an error page, e.g., non-human clients do
	 * not analyze it anyway but have to consume the response (wasted time and resources). When a
	 * client issues a request, the server will write the error messages to either one header:
	 * {@code Auth-Error} or {@code Server-Error}.
	 * <p>
	 * Technically speaking, {@link HttpServletResponse#setStatus(int)} will be called instead of
	 * {@link HttpServletResponse#sendError(int, String)}.
	 *
	 * @param errorMessagesAsHeaders
	 *            indicates whether error messages will be responded as headers
	 */
	public void setErrorMessagesAsHeaders(boolean errorMessagesAsHeaders) {
		this.errorMessagesAsHeaders = errorMessagesAsHeaders;
	}

	protected void respondErrorMessage(Request request, Response response, int statusCode,
			String messageKey, Object... params) throws IOException {

		String message = null;
		if(!omitErrorMessages && StringUtils.isNotEmpty(messageKey))
			message = sm.getString(messageKey, params);

		if (errorMessagesAsHeaders) {
			if (StringUtils.isNotEmpty(message)) {
				String headerName;
				switch (statusCode) {
				case HttpServletResponse.SC_UNAUTHORIZED:
					headerName = "Auth-Error";
					break;
				case HttpServletResponse.SC_INTERNAL_SERVER_ERROR:
					headerName = "Server-Error";
					break;
				default:
					throw new IllegalArgumentException(String.format(
							"Status code %d not supported", statusCode));
				}

				response.setHeader(headerName, message);
			}

			response.setStatus(statusCode);
		} else
			response.sendError(statusCode, message);

	}

	protected void sendInternalServerError(Request request, Response response, String messageKey,
			Object... params) throws IOException {
		respondErrorMessage(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
				messageKey, params);
	}

	protected void sendUnauthorized(Request request, Response response, String scheme)
			throws IOException {
		sendUnauthorized(request, response, scheme, null);
	}

	protected void sendUnauthorized(Request request, Response response, String scheme,
			String messageKey, Object... params) throws IOException {
		response.addHeader("WWW-Authenticate", scheme);

		respondErrorMessage(request, response, HttpServletResponse.SC_UNAUTHORIZED, messageKey,
				params);
	}

}
