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

/**
 * A base mapper for the AD attribute {@code sAMAccountName} and the realm.
 */
public abstract class SamAccountNameMapper implements UsernameSearchMapper {

	protected static class SamAccountNameMappedValues implements MappedValues {

		private String searchBase;
		private String searchUsername;

		protected SamAccountNameMappedValues(String searchBase, String searchUsername) {
			this.searchBase = searchBase;
			this.searchUsername = searchUsername;
		}

		@Override
		public String getSearchBase() {
			return searchBase;
		}

		@Override
		public String getSearchAttributeName() {
			return "sAMAccountName";
		}

		@Override
		public String getSearchUsername() {
			return searchUsername;
		}

	}

}
