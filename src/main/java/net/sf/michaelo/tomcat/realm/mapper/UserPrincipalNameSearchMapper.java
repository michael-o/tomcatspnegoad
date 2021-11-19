/*
 * Copyright 2013–2021 Michael Osipov
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
package net.sf.michaelo.tomcat.realm.mapper;

import java.util.Arrays;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * A mapper for the AD attribute {@code userPrincipalName}. This mapper maps the GSS name to the AD
 * attribute {@code userPrincipalName} which by default contains the implicit UPN unless it's
 * overwritten by the explicit (enterprise) UPN. In this case, the result will be empty. No
 * assumption is made about the root DN set in the given context, so you can narrow down your search
 * base if you like.
 */
public class UserPrincipalNameSearchMapper implements UsernameSearchMapper {

	protected final static Oid KRB5_NT_PRINCIPAL;
	protected final static Oid KRB5_NT_ENTERPRISE_PRINCIPAL;
	protected final static Oid MS_UPN;

	static {
		try {
			KRB5_NT_PRINCIPAL = new Oid("1.2.840.113554.1.2.2.1");
		} catch (GSSException e) {
			throw new IllegalStateException("Failed to create OID for KRB5_NT_PRINCIPAL");
		}

		try {
			KRB5_NT_ENTERPRISE_PRINCIPAL = new Oid("1.2.840.113554.1.2.2.6");
		} catch (GSSException e) {
			throw new IllegalStateException("Failed to create OID for KRB5_NT_ENTERPRISE_PRINCIPAL");
		}

		try {
			MS_UPN = new Oid("1.3.6.1.4.1.311.20.2.3");
		} catch (GSSException e) {
			throw new IllegalStateException("Failed to create OID for MS_UPN");
		}
	}

	private static final Oid[] SUPPORTED_STRING_NAME_TYPES = new Oid[] { MS_UPN, KRB5_NT_ENTERPRISE_PRINCIPAL,
			KRB5_NT_PRINCIPAL };

	@Override
	public Oid[] getSupportedStringNameTypes() {
		return Arrays.copyOf(SUPPORTED_STRING_NAME_TYPES, SUPPORTED_STRING_NAME_TYPES.length);
	}

	@Override
	public boolean supportsGssName(GSSName gssName) {
		try {
			return gssName.getStringNameType().containedIn(SUPPORTED_STRING_NAME_TYPES);
		} catch (GSSException e) {
			// Can this ever happen?
			return false;
		}
	}

	protected static class UserPrincipalNameMappedValues implements MappedValues {

		private String searchUsername;

		protected UserPrincipalNameMappedValues(String searchUsername) {
			this.searchUsername = searchUsername;
		}

		@Override
		public String getSearchBase() {
			return StringUtils.EMPTY;
		}

		@Override
		public String getSearchAttributeName() {
			return "userPrincipalName";
		}

		@Override
		public String getSearchUsername() {
			return searchUsername;
		}

	}

	public synchronized MappedValues map(DirContext context, GSSName gssName)
			throws NamingException {
		if (!supportsGssName(gssName))
			throw new IllegalArgumentException("GSS name '" + gssName + "' is not supported");

		return new UserPrincipalNameMappedValues(gssName.toString());
	}

}
