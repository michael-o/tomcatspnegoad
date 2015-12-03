/*
 * Copyright 2013–2015 Michael Osipov
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import javax.naming.CompositeName;
import javax.naming.InvalidNameException;
import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import net.sf.michaelo.dirctxsrc.DirContextSource;
import net.sf.michaelo.tomcat.realm.mapper.SamAccountNameRfc2247Mapper;
import net.sf.michaelo.tomcat.realm.mapper.UserPrincipalNameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper.MappedValues;
import net.sf.michaelo.tomcat.utils.LdapUtils;

import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * A realm which retrieves authenticated users from Active Directory.
 *
 * <p>
 * Following options can be configured:
 * <ul>
 * <li>{@code resourceName}: The name of the {@link DirContextSource} in JNDI with which principals
 * will be retrieved.</li>
 * <li>{@code localResource}: Whether this resource is locally configured in the {@code context.xml}
 * or globally configured in the {@code server.xml} (optional). Default value is {@code false}.</li>
 * </ul>
 * </p>
 * <p>
 *
 * @see ActiveDirectoryPrincipal
 * @version $Id$
 */
public class ActiveDirectoryRealm extends GssAwareRealmBase<DirContextSource> {

	private static final UsernameSearchMapper[] USERNAME_SEARCH_MAPPERS = {
			new SamAccountNameRfc2247Mapper(), new UserPrincipalNameSearchMapper() };

	@Override
	public String getInfo() {
		return "net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm/1.1";
	}

	@Override
	protected String getName() {
		return "ActiveDirectoryRealm";
	}

	@Override
	public Principal authenticate(GSSName gssName, Oid mech, GSSCredential delegatedCredential) {

		DirContextSource dirContextSource = null;
		try {
			dirContextSource = lookupResource();
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryealm.lookupFailed", resourceName), e);

			return null;
		}

		DirContext context = null;
		try {
			context = dirContextSource.getDirContext();
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.obtainFailed", resourceName), e);

			return null;
		}

		Principal principal = null;
		try {
			User user = getUser(context, gssName);

			if (user != null) {
				List<String> roles = getRoles(context, user);

				principal = new ActiveDirectoryPrincipal(gssName, mech, user.getSid(),
						user.getDn(), delegatedCredential, roles);
			}

		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.principalSearchFailed", gssName), e);

			return null;
		} finally {
			LdapUtils.close(context);
		}

		return principal;
	}

	@Override
	public boolean hasRole(Principal principal, String role) {

		if (principal == null || role == null || !(principal instanceof ActiveDirectoryPrincipal))
			return false;

		ActiveDirectoryPrincipal adp = (ActiveDirectoryPrincipal) principal;
		boolean result = adp.hasRole(role);

		if (logger.isDebugEnabled()) {
			if (result)
				logger.debug(sm.getString("activeDirectoryRealm.hasRole", principal, role));
			else
				logger.debug(sm.getString("activeDirectoryRealm.hasNotRole", principal, role));
		}

		return result;
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

			if (!results.hasMore()) {

				if (logger.isDebugEnabled()) {
					String simpleClassName = mapper.getClass().getSimpleName();
					logger.debug(sm.getString("activeDirectoryRealm.usernameNotMapped",
							searchAttributeValue, searchBase, searchAttributeName, simpleClassName));
				}

				LdapUtils.close(results);
			} else
				break;
		}

		if (!results.hasMore()) {
			logger.info(sm.getString("activeDirectoryRealm.userNotFound", gssName));

			return null;
		}

		SearchResult result = results.next();

		if (results.hasMore()) {
			logger.error(sm.getString("activeDirectoryRealm.duplicateUser", gssName));

			LdapUtils.close(results);
			return null;
		}

		LdapName dn = getDistinguishedName(context, searchBase, result);
		byte[] sidBytes = (byte[]) result.getAttributes().get("objectSid;binary").get();
		Sid sid = new Sid(sidBytes);

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.userFound", gssName, dn, sid));

		Attribute memberOfAttr = result.getAttributes().get("memberOf");

		List<String> roles = new LinkedList<String>();

		if (memberOfAttr != null && memberOfAttr.size() > 0) {
			NamingEnumeration<?> memberOfValues = memberOfAttr.getAll();

			while (memberOfValues.hasMore())
				roles.add((String) memberOfValues.next());
		}

		return new User(gssName, sid, dn, roles);
	}

	protected List<String> getRoles(DirContext context, User user) throws NamingException {

		List<String> roles = new LinkedList<String>();

		if (logger.isTraceEnabled())
			logger.trace(sm.getString("activeDirectoryRealm.retrievingRoles", user.getGssName()));

		for (String role : user.getRoles()) {
			String roleRdn = getRelativeName(context, role);

			Attributes roleAttributes = context.getAttributes(roleRdn, new String[] { "sAMAccountName" });
			String samAccountName = (String) roleAttributes.get("sAMAccountName").get();

			NameParser parser = context.getNameParser(StringUtils.EMPTY);
			LdapName roleDn = (LdapName) parser.parse(role);

			List<String> realmComponents = new ArrayList<String>();
			for (Rdn rdn : roleDn.getRdns()) {
				if (rdn.getType().equals("DC"))
					realmComponents.add(((String) rdn.getValue()).toUpperCase(Locale.ROOT));
				else
					break;
			}

			Collections.reverse(realmComponents);
			String realm = StringUtils.join(realmComponents, '.');

			String principal = String.format("%s@%s", samAccountName, realm);
			roles.add(principal);

			if (logger.isTraceEnabled())
				logger.trace(sm.getString("activeDirectoryRealm.foundRoleConverted", roleDn,
						principal));
		}

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.foundRolesCount", roles.size(),
					user.getGssName()));
		if (logger.isTraceEnabled())
			logger.trace(sm.getString("activeDirectoryRealm.foundRoles", user.getGssName(), roles));

		return roles;
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
			try {
				// Normalize the name by running it through the name parser.
				NameParser parser = context.getNameParser(StringUtils.EMPTY);
				URI userNameUri = new URI(absoluteName);
				String pathComponent = userNameUri.getPath();
				// Should not ever have an empty path component, since that is
				// /{DN}
				if (pathComponent.length() < 1) {
					throw new InvalidNameException(sm.getString(
							"activeDirectoryRealm.unparseableName", absoluteName));
				}
				Name name = parser.parse(pathComponent.substring(1));
				return (LdapName) name;
			} catch (URISyntaxException e) {
				throw new InvalidNameException(sm.getString("activeDirectoryRealm.unparseableName",
						absoluteName));
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
		private final Sid sid;
		private final LdapName dn;
		private final List<String> roles;

		public User(GSSName gssName, Sid sid, LdapName dn, List<String> roles) {
			this.gssName = gssName;
			this.sid = sid;
			this.dn = (LdapName) dn.clone();

			if (roles == null || roles.isEmpty())
				this.roles = Collections.emptyList();
			else
				this.roles = Collections.unmodifiableList(roles);
		}

		public GSSName getGssName() {
			return gssName;
		}

		public Sid getSid() {
			return sid;
		}

		public LdapName getDn() {
			return (LdapName) dn.clone();
		}

		public List<String> getRoles() {
			return roles;
		}

	}

}
