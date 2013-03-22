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


public class SamAccountNameRfc2247Mapper extends SamAccountNameMapper {

	private static final Log logger = LogFactory
			.getLog(SamAccountNameRfc2247Mapper.class);

	public synchronized MappedValues map(DirContext context,
			String username) throws NamingException {

		String searchUsername = StringUtils.substringBefore(username, "@");
		String realm = StringUtils.substringAfter(username, "@");
		String searchBase = StringUtils.EMPTY;

		if (logger.isTraceEnabled())
			logger.trace(String.format("Retrieving DN for realm '%s'", realm));

		String[] realmComponents = StringUtils.split(realm, '.');
		ArrayUtils.reverse(realmComponents);
		NameParser parser = context.getNameParser(StringUtils.EMPTY);
		Name searchBaseName = parser.parse(StringUtils.EMPTY);

		Name realmComponentName;
		for (String realmComponent : realmComponents) {
			realmComponentName = parser.parse("DC="
					+ realmComponent.toLowerCase(Locale.ENGLISH));
			searchBaseName.addAll(realmComponentName);
		}

		searchBase = searchBaseName.toString();

		return new SamAccountNameMappedValues(searchBase, searchUsername);

	}
}
