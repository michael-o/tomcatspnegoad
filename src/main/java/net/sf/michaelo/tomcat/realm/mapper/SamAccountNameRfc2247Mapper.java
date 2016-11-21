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
package net.sf.michaelo.tomcat.realm.mapper;

import java.util.Locale;

import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSName;

/**
 * A mapper for the AD attribute {@code sAMAccountName} and the realm. This mapper splits the GSS
 * name in the primary and realm component. The instance component is completely ignored. The
 * primary component is assigned to the {@code sAMAccountName} and the realm is transformed to a
 * search base according to <a href="http://www.ietf.org/rfc/rfc2247.txt">RFC 2247</a>. Moreover,
 * this implementation mimics
 * <a href="https://msdn.microsoft.com/en-us/library/ms675970%28v=vs.85%29.aspx">
 * {@code DsCrackNames}</a> with {@code formatOffered} set to {@code DS_USER_PRINCIPAL_NAME} and
 * {@code formatDesired} set to {@code DS_FQDN_1779_NAME}. Verified against <a href=
 * "https://github.com/samba-team/samba/blob/7ed24924d2917556a03c51eadcb65b3e3c1e8af6/source4/dsdb/samdb/cracknames.c#L1260">
 * Samba's implementation</a> of {@code DsCrackNames}.
 * <p>
 * <strong>Note:</strong> This mapper requires to operate from the {@code RootDSE} of a domain
 * controller or better yet, a GC. No root DN normalization (stripping DC components) happens here
 * (yet).
 *
 * @version $Id$
 */
public class SamAccountNameRfc2247Mapper extends SamAccountNameMapper {

	public synchronized MappedValues map(DirContext context, GSSName gssName)
			throws NamingException {

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
