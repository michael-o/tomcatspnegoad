/*
 * Copyright 2013–2015 Michael Osipov
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

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.ietf.jgss.GSSName;

/**
 * A mapper for the AD attribute {@code sAMAccountName} and the realm. This mapper splits the
 * GSS name in the primary and realm components. The instance component is completely
 * ignored. The primary component is assigned to the {@code sAMAccountName} and the realm is
 * transformed to a search base according to <a href="http://www.ietf.org/rfc/rfc2247.txt">RFC
 * 2247</a>. <br/>
 * This mapper requires to operate from the {@code RootDSE} of a domain controller or better yet, a
 * GC. No root DN normalization (stripping DC components) happens here (yet).
 *
 * @version $Id$
 */
public class SamAccountNameRfc2247Mapper extends SamAccountNameMapper {

	private static final Log logger = LogFactory.getLog(SamAccountNameRfc2247Mapper.class);

	public synchronized MappedValues map(DirContext context, GSSName gssName)
			throws NamingException {

		// TODO Maybe use a Kerberos principal to extract components?
		String searchUsername = StringUtils.substringBefore(gssName.toString(), "@");
		String realm = StringUtils.substringAfter(gssName.toString(), "@");
		String searchBase = StringUtils.EMPTY;

		if (logger.isTraceEnabled())
			logger.trace(String.format("Retrieving DN for realm '%s'", realm));

		String[] realmComponents = StringUtils.split(realm, '.');
		ArrayUtils.reverse(realmComponents);
		NameParser parser = context.getNameParser(StringUtils.EMPTY);
		Name searchBaseName = parser.parse(StringUtils.EMPTY);

		Name realmComponentName;
		for (String realmComponent : realmComponents) {
			realmComponentName = parser.parse("DC=" + realmComponent.toLowerCase(Locale.ENGLISH));
			searchBaseName.addAll(realmComponentName);
		}

		searchBase = searchBaseName.toString();

		return new SamAccountNameMappedValues(searchBase, searchUsername);

	}
}
