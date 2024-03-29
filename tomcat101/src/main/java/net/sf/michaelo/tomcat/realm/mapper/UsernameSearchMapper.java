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

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm;

/**
 * A mapper interface (strategy pattern) for translating GSS names to Active Directory search
 * space parameters.
 */
public interface UsernameSearchMapper {

	/**
	 * Mapped values holder. The {@link ActiveDirectoryRealm} uses these mapped values to search for
	 * a user.
	 */
	interface MappedValues {

		String getSearchBase();

		String getSearchAttributeName();

		String getSearchUsername();

	}

	/**
	 * Returns an array of name type OIDs which a mapper is able to map into AD search space.
	 *
	 * @return supported string name type OIDs
	 */
	Oid[] getSupportedStringNameTypes();


	/**
	 * Determines whether a mapper is able to map a given GSS name into AD search space.
	 *
	 * @param gssName the gssName to test
	 * @return {@code} if this mapper is able to map a name, {@code false} otherwise
	 */
	boolean supportsGssName(GSSName gssName);

	/**
	 * Maps a GSS name to AD search space parameters. A mapper implementation must assure that the
	 * user can be found in the given {@code context} when an approriate GSS name is presented. The
	 * implementor must be aware that the returned search base might need to be relativized to the
	 * root DN of the context.
	 *
	 * @param context
	 *            the search context
	 * @param gssName
	 *            the GSS name to be mapped
	 * @return mapped values for user retrieval
	 * @throws NamingException
	 *             if a context-related error has occured
	 * @throws IllegalArgumentException
	 *             if the GSS name is not supported
	 */
	MappedValues map(DirContext context, GSSName gssName) throws NamingException;

}
