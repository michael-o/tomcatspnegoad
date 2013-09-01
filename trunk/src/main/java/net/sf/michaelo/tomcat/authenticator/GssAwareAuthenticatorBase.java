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

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Globals;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Base authenticator for GSS-based authenticators, which holds the login entry name.
 *
 * @version $Id$
 */
abstract class GssAwareAuthenticatorBase extends AuthenticatorBase {

	protected final Log logger = LogFactory.getLog(getClass());

	private String loginEntryName;

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

	protected void sendException(Request request, Response response, AuthenticationException e)
			throws IOException {
		request.setAttribute(Globals.EXCEPTION_ATTR, e);
		response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
	}

}
