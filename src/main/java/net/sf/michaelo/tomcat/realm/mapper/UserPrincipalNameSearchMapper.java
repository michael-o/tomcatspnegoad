package net.sf.michaelo.tomcat.realm.mapper;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.apache.commons.lang3.StringUtils;


public class UserPrincipalNameSearchMapper implements UsernameSearchMapper {

	protected static class UserPrincipalNameMappedValues implements
			MappedValues {

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

	public synchronized MappedValues map(DirContext context,
			String username) throws NamingException {

		return new UserPrincipalNameMappedValues(username);

	}

}
