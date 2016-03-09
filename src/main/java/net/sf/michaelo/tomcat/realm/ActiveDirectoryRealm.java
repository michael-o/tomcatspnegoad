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
package net.sf.michaelo.tomcat.realm;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

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

import net.sf.michaelo.dirctxsrc.DirContextSource;
import net.sf.michaelo.tomcat.realm.mapper.SamAccountNameRfc2247Mapper;
import net.sf.michaelo.tomcat.realm.mapper.UserPrincipalNameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper.MappedValues;
import net.sf.michaelo.tomcat.utils.LdapUtils;

import org.apache.catalina.Context;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

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
 * <li>{@code additionalAttributes}: Comma-separated list of attributes to be retrieved for the
 * principal. Binary attributes must succeed with {@code ;binary} and will be stored as
 * {@code byte[]}, ordinary attributes will be stored as {@code String}. If an attribute is multivalued,
 * it will be stored as {@code List}.</li>
 * <li>{@code storeDelegatedCredential}: Store the client's (initiator's) delegated credential in
 * the user principal (optional). Valid values are {@code true}, {@code false}. Default value is
 * {@code false}.</li>
 * </ul>
 * </p>
 * <p>
 * By default the SIDs ({@code objectSid} and {@code sIDHistory}) of the Active Directory security
 * groups will be retreived.
 * </p>
 *
 * @see ActiveDirectoryPrincipal
 * @version $Id$
 */
public class ActiveDirectoryRealm extends GssAwareRealmBase<DirContextSource> {

	private static final UsernameSearchMapper[] USERNAME_SEARCH_MAPPERS = {
			new SamAccountNameRfc2247Mapper(), new UserPrincipalNameSearchMapper() };

	private static final String[] DEFAULT_ATTRIBUTES = new String[] { "memberOf",
			"objectSid;binary" };

	private String[] additionalAttributes;
	protected boolean storeDelegatedCredential;

	@Override
	public String getInfo() {
		return "net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm/2.0";
	}

	@Override
	protected String getName() {
		return "ActiveDirectoryRealm";
	}

	// TODO Document me!
	public void setAdditionalAttributes(String additionalAttributes) {
		this.additionalAttributes = additionalAttributes.split(",");
	}

	/**
	 * Sets whether client's (initiator's) delegated credential is stored in the user principal.
	 *
	 * @param storeDelegatedCredential
	 *            the store delegated credential indication
	 */
	public void setStoreDelegatedCredential(boolean storeDelegatedCredential) {
		this.storeDelegatedCredential = storeDelegatedCredential;
	}

	@Override
	public Principal authenticate(GSSName gssName) {
		return authenticateInternal(gssName, null);
	}

	@Override
	public Principal authenticate(GSSContext gssContext) {
		if(gssContext == null)
			throw new NullPointerException("gssContext cannot be null");

		if(!gssContext.isEstablished())
			throw new IllegalStateException("gssContext is not fully established");

		GSSName gssName;
		GSSCredential delegatedCredential = null;

		try {
			gssName = gssContext.getSrcName();

			if (storeDelegatedCredential) {
				if (gssContext.getCredDelegState()) {
					delegatedCredential = gssContext.getDelegCred();
				} else if (logger.isDebugEnabled())
					logger.debug(sm.getString("activeDirectoryRealm.credentialNotDelegable",
							gssName));
			}
		} catch (GSSException e) {
			logger.error(sm.getString("realm.inquireFailed"), e);

			return null;
		}

		return authenticateInternal(gssName, delegatedCredential);
	}

	private Principal authenticateInternal(GSSName gssName, GSSCredential delegatedCredential) {
		if(gssName == null)
			throw new NullPointerException("gssName cannot be null");

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

				principal = new ActiveDirectoryPrincipal(gssName, user.getSid(), delegatedCredential,
						roles, user.getAdditionalAttributes());
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

		boolean result;
		if(container instanceof Context) {
			Context context = (Context) container;
			result = adp.hasRole(context.findRoleMapping(role));
		} else
			result = adp.hasRole(role);

		if (logger.isDebugEnabled()) {
			if (result)
				logger.debug(sm.getString("activeDirectoryRealm.hasRole", principal, role));
			else
				logger.debug(sm.getString("activeDirectoryRealm.hasNotRole", principal, role));
		}

		return result;
	}

	protected User getUser(DirContext context, GSSName gssName) throws NamingException {

		String[] attributes = DEFAULT_ATTRIBUTES;

		if(ArrayUtils.isNotEmpty(additionalAttributes))
			attributes = ArrayUtils.addAll(DEFAULT_ATTRIBUTES, additionalAttributes);

		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchCtls.setReturningAttributes(attributes);

		// Query for user and machine accounts only
		String searchFilterPattern = "(&(|(sAMAccountType=805306368)(sAMAccountType=805306369))(%s={0}))";

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

			LdapUtils.close(memberOfValues);
		}

		Map<String, Object> additionalAttributesMap = Collections.emptyMap();

		if(ArrayUtils.isNotEmpty(additionalAttributes)) {
			additionalAttributesMap = new HashMap<String, Object>();

			for(String addAttr : additionalAttributes) {
				Attribute attr = result.getAttributes().get(addAttr);

				if(attr != null && attr.size() > 0) {
					if(attr.size() > 1) {
						List<Object> attrList = new ArrayList<Object>(attr.size());
						NamingEnumeration<?> attrEnum = attr.getAll();

						while(attrEnum.hasMore())
							attrList.add(attrEnum.next());

						LdapUtils.close(attrEnum);

						additionalAttributesMap.put(addAttr, Collections.unmodifiableList(attrList));
					} else
						additionalAttributesMap.put(addAttr, attr.get());
				}
			}
		}

		return new User(gssName, sid, roles, additionalAttributesMap);
	}

	protected List<String> getRoles(DirContext context, User user) throws NamingException {

		List<String> roles = new LinkedList<String>();

		if (logger.isTraceEnabled())
			logger.trace(sm.getString("activeDirectoryRealm.retrievingRoles", user.getGssName()));

		for (String role : user.getRoles()) {
			String roleRdn = getRelativeName(context, role);

			Attributes roleAttributes = context.getAttributes(roleRdn, new String[] { "groupType",
					"objectSid;binary", "sIDHistory;binary" });

			int groupType = Integer.parseInt((String) roleAttributes.get("groupType").get());

			// Skip distribution groups, i.e., we want security-enabled groups only
			// (ADS_GROUP_TYPE_SECURITY_ENABLED)
			if ((groupType & Integer.MIN_VALUE) == 0) {
				if (logger.isTraceEnabled())
					logger.trace(sm.getString("activeDirectoryRealm.skippingDistributionRole", role));
				continue;
			}

			byte[] objectSidBytes = (byte[]) roleAttributes.get("objectSid;binary").get();
			String sidString = new Sid(objectSidBytes).toString();

			Attribute sidHistory = roleAttributes.get("sIDHistory;binary");
			List<String> sidHistoryStrings = new LinkedList<String>();
			if (sidHistory != null) {
				NamingEnumeration<?> sidHistoryEnum = sidHistory.getAll();
				while (sidHistoryEnum.hasMore()) {
					byte[] sidHistoryBytes = (byte[]) sidHistoryEnum.next();
					sidHistoryStrings.add(new Sid(sidHistoryBytes).toString());
				}

				LdapUtils.close(sidHistoryEnum);
			}

			roles.add(sidString);
			roles.addAll(sidHistoryStrings);

			if (logger.isTraceEnabled()) {
				if (sidHistoryStrings.isEmpty())
					logger.trace(sm.getString("activeDirectoryRealm.foundRoleConverted", role,
							sidString));
				else
					logger.trace(sm.getString(
							"activeDirectoryRealm.foundRoleConverted.withSidHistory", role,
							sidString, sidHistoryStrings));
			}
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
		private final List<String> roles;
		private final Map<String, Object> additionalAttributes;

		public User(GSSName gssName, Sid sid, List<String> roles, Map<String, Object> additionalAttributes) {
			this.gssName = gssName;
			this.sid = sid;
			this.roles = roles;
			this.additionalAttributes = additionalAttributes;
		}

		public GSSName getGssName() {
			return gssName;
		}

		public Sid getSid() {
			return sid;
		}

		public List<String> getRoles() {
			return roles;
		}

		public Map<String, Object> getAdditionalAttributes() {
			return additionalAttributes;
		}

	}

}
