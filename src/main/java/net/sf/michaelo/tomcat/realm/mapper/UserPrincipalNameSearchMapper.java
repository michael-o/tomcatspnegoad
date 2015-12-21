/*
 * Copyright 2013–2016 Michael Osipov
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

import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSName;

/**
 * A mapper for the AD attribute {@code userPrincipalName}. This mapper maps the GSS name to the AD
 * attribute {@code userPrincipalName} which by default contains the implicit UPN unless it's
 * overwritten by the explicit (enterprise) UPN. No assumption is made about the root DN set in the
 * given context, so you can narrow down your search base if you like.
 * 
 * @version $Id$
 */
public class UserPrincipalNameSearchMapper implements UsernameSearchMapper {

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

		return new UserPrincipalNameMappedValues(gssName.toString());
	}

}
