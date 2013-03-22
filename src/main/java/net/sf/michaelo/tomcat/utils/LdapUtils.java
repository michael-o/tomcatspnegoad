package net.sf.michaelo.tomcat.utils;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

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
