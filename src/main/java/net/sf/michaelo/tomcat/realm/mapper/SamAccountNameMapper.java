package net.sf.michaelo.tomcat.realm.mapper;

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
