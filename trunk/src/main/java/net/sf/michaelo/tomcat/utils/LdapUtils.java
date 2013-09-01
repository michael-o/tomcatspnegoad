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
package net.sf.michaelo.tomcat.utils;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

/**
 * Utilities for closing LDAP resources.
 *
 * @version $Id$
 */
public class LdapUtils {

	public static void close(DirContext context) {

		if (context == null)
			return;

		try {
			context.close();
		} catch (NamingException e) {
		}

	}

	public static void close(NamingEnumeration<?> results) {

		if (results == null)
			return;

		try {
			results.close();
		} catch (NamingException e) {
		}

	}

}
