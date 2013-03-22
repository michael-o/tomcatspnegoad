package net.sf.michaelo.tomcat.realm.mapper;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;


public interface UsernameSearchMapper {

	interface MappedValues {

		String getSearchBase();

		String getSearchAttributeName();

		String getSearchUsername();

	}

	MappedValues map(DirContext context, String username) throws NamingException;

}
