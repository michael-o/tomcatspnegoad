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
package net.sf.michaelo.tomcat.realm.mapper;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm;

/**
 * A mapper interface (strategy pattern) for translating Kerberos principals to Active Directory
 * search parameters.
 *
 * @version $Id$
 */
public interface UsernameSearchMapper {

	/**
	 * Mapped values holder. The {@link ActiveDirectoryRealm} uses this mapped values to search for
	 * a user.
	 */
	interface MappedValues {

		String getSearchBase();

		String getSearchAttributeName();

		String getSearchUsername();

	}

	/**
	 * Maps a Kerberos principal to AD search parameters. A mapper implementation must assure that
	 * the user can be found in the given {@code context} when an approriate username is presented.
	 * The implementor must be aware that the returned search base might need to be normalized to
	 * the root DN of the context.
	 *
	 * @param context
	 *            the search context
	 * @param username
	 *            the user principal to be mapped
	 * @return mapped values for user retrieval
	 * @throws NamingException
	 *             if context-related errors occured
	 */
	MappedValues map(DirContext context, String username) throws NamingException;

}
