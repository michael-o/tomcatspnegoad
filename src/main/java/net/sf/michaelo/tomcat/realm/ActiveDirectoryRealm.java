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
package net.sf.michaelo.tomcat.realm;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.naming.CompositeName;
import javax.naming.InvalidNameException;
import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

import net.sf.michaelo.dirctxsrc.DirContextSource;
import net.sf.michaelo.tomcat.realm.mapper.SamAccountNameRfc2247Mapper;
import net.sf.michaelo.tomcat.realm.mapper.UserPrincipalNameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper.MappedValues;
import net.sf.michaelo.tomcat.utils.LdapUtils;

import org.apache.catalina.util.HexUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * A realm which retrieves authenticated user from Active Directory.
 *
 * <p>
 * Following options can be configured:
 * <li>{@code resourceName}: The name of the {@link DirContextSource} in JNDI with which principals
 * will be retrieved.</li>
 * <li>{@code localResource}: Whether this resource is locally configured in the {@code context.xml}
 * or globally configured in the {@code server.xml} (optional). Default value is {@code false}.</li>
 * <li>{@code strippableRoleNamePrefixes}: Role name prefixes (comma-separated) which can be
 * stripped during retrieval (optional).</li>
 * </ul>
 * </p>
 * <p>
 *
 * @version $Id$
 */
public class ActiveDirectoryRealm extends GssAwareRealmBase<DirContextSource> {

	private static final UsernameSearchMapper[] USERNAME_SEARCH_MAPPERS = {
			new SamAccountNameRfc2247Mapper(), new UserPrincipalNameSearchMapper() };

	private String[] strippableRoleNamePrefixes;

	@Override
	public String getInfo() {
		return "net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm/0.9";
	}

	@Override
	protected String getName() {
		return "ActiveDirectoryRealm";
	}

	/**
	 * Retrieves the roles for a specific user from Active Directory. The roles will be stripped by
	 * the CN by default.
	 *
	 * @param user
	 *            the user for role retrievement
	 * @return roles list for the given pricipal
	 */
	protected List<String> getRoles(User user) throws NamingException {

		List<String> roles = new LinkedList<String>();

		if (logger.isTraceEnabled())
			logger.trace(String.format("Retrieving roles for user '%s' with DN '%s'",
					user.getGssName(), user.getDn()));

		for (String role : user.getRoles()) {
			role = StringUtils.substringBetween(role, "CN=", ",");
			if (strippableRoleNamePrefixes != null) {
				for (String prefix : strippableRoleNamePrefixes) {
					if (role.startsWith(prefix))
						roles.add(StringUtils.substringAfter(role, prefix));
					else
						roles.add(role);
				}
			} else
				roles.add(role);
		}

		if (logger.isDebugEnabled())
			logger.debug(String.format("Found %s roles for user '%s'", roles.size(),
					user.getGssName()));
		if (logger.isTraceEnabled())
			logger.debug(String.format("Found following roles %s for user '%s'", roles,
					user.getGssName()));

		return roles;
	}

	@Override
	public boolean hasRole(Principal principal, String role) {

		if (principal == null || role == null || !(principal instanceof ActiveDirectoryPrincipal))
			return false;

		ActiveDirectoryPrincipal adp = (ActiveDirectoryPrincipal) principal;
		boolean result = adp.hasRole(role);

		if (logger.isDebugEnabled()) {
			if (result)
				logger.debug(String.format("Principal '%s' does not have role '%s'", principal, role));
			else
				logger.debug(String.format("Principal '%s' has role '%s'", principal, role));
		}

		return result;
	}

	/**
	 * Sets the role name prefixed which can be stripped during retrieval.
	 *
	 * @param prefixes
	 *            the strippable role name prefixes
	 */
	public void setStrippableRoleNamePrefixes(String prefixes) {
		this.strippableRoleNamePrefixes = StringUtils.split(prefixes, ",");
	}

	@Override
	public Principal authenticate(GSSName gssName, Oid mech, GSSCredential delegatedCredential) {

		DirContextSource dirContextSource = null;
		try {
			dirContextSource = (DirContextSource) lookupResource();
		} catch (NamingException e) {
			logger.error(String.format(
					"Could not retrieve the DirContextSource '%s' from JNDI context", resourceName));
			throw new RuntimeException(String.format("Failed to retrieve resource '%s'",
					resourceName), e);
		}

		DirContext context = null;
		try {
			context = dirContextSource.getDirContext();
		} catch (NamingException e) {
			logger.error(String.format("Could not retrieve DirContext from DirContextSource '%s'",
					resourceName), e);
			throw new RuntimeException(e);
		}

		Principal principal = null;
		try {
			User user = getUser(context, gssName);
			List<String> roles = null;
			if (user != null)
				roles = getRoles(user);

			if (user != null) {
				principal = new ActiveDirectoryPrincipal(gssName, mech, user.getSid(),
						user.getDn(), delegatedCredential, roles);
			}

		} catch (NamingException e) {
			logger.error(
					String.format("Unable to perform principal search for user '%s'", gssName), e);
			throw new RuntimeException(e);
		} finally {
			LdapUtils.close(context);
		}

		return principal;
	}

	protected User getUser(DirContext context, GSSName gssName) throws NamingException {

		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchCtls.setReturningAttributes(new String[] { "memberOf", "objectSid;binary" });
		String searchFilterPattern = "(&(objectClass=user)(%s={0})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

		String searchFilter;
		String searchBase = null;
		String searchAttributeName;
		String searchAttributeValue;

		MappedValues mappedValues;
		NamingEnumeration<SearchResult> results = null;
		for (UsernameSearchMapper mapper : USERNAME_SEARCH_MAPPERS) {
			mappedValues = mapper.map(context, gssName);

			searchBase = getRelativeName(context, mappedValues.getSearchBase());
			searchAttributeName = mappedValues.getSearchAttributeName();
			searchAttributeValue = mappedValues.getSearchUsername();

			searchFilter = String.format(searchFilterPattern, searchAttributeName);
			results = context.search(searchBase, searchFilter,
					new Object[] { searchAttributeValue }, searchCtls);

			if (results == null || !results.hasMore()) {

				if (logger.isDebugEnabled()) {
					String shortClassName = StringUtils.substringAfterLast(mapper.getClass()
							.getName(), ".");
					logger.debug(String
							.format("Username '%s' in search base '%s' and search attribute '%s' with mapper '%s' not found, trying fallback",
									searchAttributeValue, searchBase, searchAttributeName,
									shortClassName));
				}

				LdapUtils.close(results);
			} else
				break;
		}

		if (results == null || !results.hasMore()) {
			logger.info(String.format("User '%s' not found", gssName));
			return null;
		}

		SearchResult result = results.next();

		if (results.hasMore()) {
			logger.warn(String.format("User '%s' has multiple entries", gssName));
			return null;
		}

		LdapName dn = getDistinguishedName(context, searchBase, result);

		if (logger.isDebugEnabled())
			logger.debug(String.format("Entry found for user '%s' with DN '%s'", gssName, dn));

		byte[] sid = (byte[]) result.getAttributes().get("objectSid;binary").get();

		if (logger.isDebugEnabled()) {
			logger.debug(String.format("Found SID '%s' for user '%s'", HexUtils.convert(sid),
					gssName));
		}

		Attribute memberOfAttr = result.getAttributes().get("memberOf");
		NamingEnumeration<?> memberOfValues = memberOfAttr.getAll();

		List<String> roles = new LinkedList<String>();

		while (memberOfValues.hasMoreElements())
			roles.add((String) memberOfValues.nextElement());

		LdapUtils.close(memberOfValues);

		return new User(gssName, sid, dn, roles);
	}

	/**
	 * Returns the distinguished name of a search result.
	 *
	 * @param context
	 *            Our DirContext
	 * @param base
	 *            The base DN
	 * @param result
	 *            The search result
	 * @return String containing the distinguished name
	 */
	protected LdapName getDistinguishedName(DirContext context, String base, SearchResult result)
			throws NamingException {
		// Get the entry's distinguished name. For relative results, this means
		// we need to composite a name with the base name, the context name, and
		// the result name. For non-relative names, use the returned name.
		if (result.isRelative()) {
			if (logger.isTraceEnabled()) {
				logger.trace(String.format("Search returned relative name '%s'", result.getName()));
			}
			NameParser parser = context.getNameParser(StringUtils.EMPTY);
			Name contextName = parser.parse(context.getNameInNamespace());
			Name baseName = parser.parse(base);

			// Bugzilla 32269
			Name entryName = parser.parse(new CompositeName(result.getName()).get(0));

			Name name = contextName.addAll(baseName);
			name = name.addAll(entryName);
			return (LdapName) name;
		} else {
			String absoluteName = result.getName();
			if (logger.isTraceEnabled())
				logger.trace(String.format("Search returned absolute name '%s'", result.getName()));
			try {
				// Normalize the name by running it through the name parser.
				NameParser parser = context.getNameParser(StringUtils.EMPTY);
				URI userNameUri = new URI(absoluteName);
				String pathComponent = userNameUri.getPath();
				// Should not ever have an empty path component, since that is
				// /{DN}
				if (pathComponent.length() < 1) {
					throw new InvalidNameException(String.format(
							"Search returned unparseable absolute name '%s'", absoluteName));
				}
				Name name = parser.parse(pathComponent.substring(1));
				return (LdapName) name;
			} catch (URISyntaxException e) {
				throw new InvalidNameException(String.format(
						"Search returned unparseable absolute name '%s'", absoluteName));
			}
		}
	}

	protected String getRelativeName(DirContext context, String distinguishedName)
			throws NamingException {

		NameParser parser = context.getNameParser(StringUtils.EMPTY);
		Name nameInNamespace = parser.parse(context.getNameInNamespace());
		Name name = parser.parse(distinguishedName);

		String nameRdn;
		String nameInNamespaceRdn;

		while (Math.min(name.size(), nameInNamespace.size()) != 0) {
			nameRdn = name.get(0);
			nameInNamespaceRdn = nameInNamespace.get(0);
			if (nameRdn.equals(nameInNamespaceRdn)) {
				name.remove(0);
				nameInNamespace.remove(0);
			} else
				break;
		}

		int innerPosn;
		while (Math.min(name.size(), nameInNamespace.size()) != 0) {
			innerPosn = nameInNamespace.size() - 1;
			nameRdn = name.get(0);
			nameInNamespaceRdn = nameInNamespace.get(innerPosn);
			if (nameRdn.equals(nameInNamespaceRdn)) {
				name.remove(0);
				nameInNamespace.remove(innerPosn);
			} else
				break;
		}

		return name.toString();

	}

	protected static class User {
		private final GSSName gssName;
		private final byte[] sid;
		private final LdapName dn;
		private final List<String> roles;

		public User(GSSName gssName, byte[] sid, LdapName dn, List<String> roles) {
			this.gssName = gssName;
			this.sid = ArrayUtils.clone(sid);
			this.dn = (LdapName) dn.clone();

			if (roles == null || roles.isEmpty())
				this.roles = Collections.emptyList();
			else
				this.roles = Collections.unmodifiableList(roles);
		}

		public GSSName getGssName() {
			return gssName;
		}

		public byte[] getSid() {
			return ArrayUtils.clone(sid);
		}

		public LdapName getDn() {
			return (LdapName) dn.clone();
		}

		public List<String> getRoles() {
			return roles;
		}

	}

}
