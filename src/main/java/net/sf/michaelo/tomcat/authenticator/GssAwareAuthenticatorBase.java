/*
 * Copyright 2013–2014 Michael Osipov
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
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

/**
 * Base authenticator for GSS-based authenticators, which holds the login entry name.
 *
 * @version $Id$
 */
abstract class GssAwareAuthenticatorBase extends AuthenticatorBase {

	protected final Log logger = LogFactory.getLog(getClass());
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

}
