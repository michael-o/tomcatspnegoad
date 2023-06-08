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
import java.util.Locale;

import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * A mapper for the AD attribute {@code sAMAccountName} and the realm. This mapper splits the GSS
 * name in the primary and realm component. The instance component is completely ignored. The
 * primary component is assigned to the {@code sAMAccountName} and the realm is transformed to a
 * search base according to <a href="https://tools.ietf.org/html/rfc2247">RFC 2247</a>. Moreover,
 * this implementation mimics
 * <a href="https://docs.microsoft.com/de-de/windows/win32/api/ntdsapi/nf-ntdsapi-dscracknamesw">
 * {@code DsCrackNames}</a> with {@code formatOffered} set to {@code DS_USER_PRINCIPAL_NAME} and
 * {@code formatDesired} set to {@code DS_FQDN_1779_NAME}. Verified against <a href=
 * "https://github.com/samba-team/samba/blob/7ed24924d2917556a03c51eadcb65b3e3c1e8af6/source4/dsdb/samdb/cracknames.c#L1260">
 * Samba's implementation</a> of {@code DsCrackNames}.
 * <p>
 * <strong>Note:</strong> This mapper requires to operate from the {@code RootDSE} of a domain
 * controller or better yet, a GC. No root DN normalization (stripping DC components) happens here
 * (yet).
 */
public class SamAccountNameRfc2247Mapper extends SamAccountNameMapper {

	protected final static Oid KRB5_NT_PRINCIPAL;

	static {
		try {
			KRB5_NT_PRINCIPAL = new Oid("1.2.840.113554.1.2.2.1");
		} catch (GSSException e) {
			throw new IllegalStateException("Failed to create OID for KRB5_NT_PRINCIPAL");
		}
	}

	private static final Oid[] SUPPORTED_STRING_NAME_TYPES = new Oid[] { KRB5_NT_PRINCIPAL };

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

	public synchronized MappedValues map(DirContext context, GSSName gssName)
			throws NamingException {
		if (!supportsGssName(gssName))
			throw new IllegalArgumentException("GSS name '" + gssName + "' is not supported");

		String[] upnComponents = StringUtils.split(gssName.toString(), '@');
		String samAccountName = upnComponents[0];
		String realm = upnComponents[1];
		String searchBase = StringUtils.EMPTY;

		String[] realmComponents = StringUtils.split(realm, '.');
		NameParser parser = context.getNameParser(StringUtils.EMPTY);
		Name searchBaseName = parser.parse(StringUtils.EMPTY);

		for (int i = realmComponents.length - 1; i >= 0; i--) {
			searchBaseName.add("DC=" + realmComponents[i].toLowerCase(Locale.ROOT));
		}

		searchBase = searchBaseName.toString();

		return new SamAccountNameMappedValues(searchBase, samAccountName);

	}
}
