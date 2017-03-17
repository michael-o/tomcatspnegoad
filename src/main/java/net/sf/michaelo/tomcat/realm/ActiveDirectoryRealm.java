/*
 * Copyright 2013–2017 Michael Osipov
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
import javax.naming.PartialResultException;
import javax.naming.ReferralException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.ManageReferralControl;
import javax.naming.ldap.Rdn;
import javax.security.sasl.SaslClient;

import net.sf.michaelo.dirctxsrc.DirContextSource;
import net.sf.michaelo.tomcat.realm.mapper.SamAccountNameRfc2247Mapper;
import net.sf.michaelo.tomcat.realm.mapper.UserPrincipalNameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper.MappedValues;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Server;
import org.apache.commons.lang3.StringUtils;
import org.apache.naming.ContextBindings;
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
 * <li>{@code dirContextSourceName}: the name of the {@link DirContextSource} in JNDI with which
 * principals will be retrieved.</li>
 * <li>{@code localDirContextSource}: whether this {@code DirContextSource} is locally configured in
 * the {@code context.xml} or globally configured in the {@code server.xml} (optional). Default
 * value is {@code false}.</li>
 * <li>{@code additionalAttributes}: comma-separated list of attributes to be retrieved for the
 * principal. Binary attributes must end with {@code ;binary} and will be stored as {@code byte[]},
 * ordinary attributes will be stored as {@code String}. If an attribute is multivalued, it will be
 * stored as {@code List}.</li>
 * </ul>
 * <p>
 * By default the SIDs ({@code objectSid} and {@code sIDHistory}) of the Active Directory security
 * groups will be retrieved.
 * <h3></h3>
 * <h4 id="referral-handling">Referral Handling</h4> When working with the default LDAP ports (not
 * GC) or in a multi-forest environment, it is highly likely to receive referrals (either
 * subordinate or cross) during a search or lookup. JNDI takes several approaches to handle
 * referrals with the {@code java.naming.referral} property and its values: {@code ignore},
 * {@code throw}, and {@code follow}. You can ignore referrals altogether, but the Active Directory
 * will still signal a {@link PartialResultException} when a {@link NamingEnumeration} is iterated.
 * The reason is because Oracle's LDAP implementation adds a {@link ManageReferralControl} when
 * {@code ignore} is set but Active Directory does not support it and returns a referral anyway.
 * This realm will catch this and continue to process the enumeration. If the
 * {@code DirContextSource} is set to {@code throw}, this realm will catch the
 * {@link ReferralException} but avoid to follow the referral(s) manually (for several reasons) and
 * will continue with the process. Following referrals automatically is a completely opaque
 * operation to the application, the {@code ReferralException} is handled internally and referral
 * contexts are queried and closed. Unfortunately, Oracle's LDAP implementation is not able to
 * handle this properly and only Oracle can fix this shortcoming. Issues have already been reported
 * (Review IDs 9089870 and 9089874, public issues
 * <a href="http://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8161361">JDK-8161361</a> and
 * <a href="http://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8160768">JDK-8161361</a>)!
 * <p>
 * <em>What is the shortcoming and how can it be solved?</em> Microsoft takes a very sophisticated
 * approach on not to rely on host names because servers can be provisioned and decommissioned any
 * time. Instead, they heavily rely on DNS domain names and DNS SRV records at runtime. I.e., an
 * initial or a referral URL does not contain a host name, but only a DNS domain name. While you can
 * connect to the service with this name, you cannot easily authenticate against it with Kerberos
 * because one cannot bind the same SPN {@code ldap/<dnsDomainName>@<REALM>}, e.g.,
 * {@code ldap/example.com@EXAMPLE.COM} to more than one account. If you try authenticate anyway,
 * you will receive a "Server not found in Kerberos database (7)" error. Therefore, one has to
 * perform a DNS SRV query ({@code _ldap._tcp.<dnsDomainName>}) to test whether this name is a host
 * name or a DNS domain name served by one or more machines. If it turns out to be a DNS domain
 * name, you have to select one target host from the query response (according to RFC 2782),
 * construct a domain-based SPN {@code ldap/<targetHost>/<dnsDomainName>@<REALM>} or a host-based
 * one {@code ldap/<targetHost>@<REALM>}, obtain a service ticket for and connect to that target
 * host. If it is a regular host name, which is not the usual case with Active Directory, Oracle's
 * internal implementation will behave correctly.<br>
 * The {@code follow} implementation cannot be made to work because there is no way to tell the
 * internal classes to perform this DNS SRV query and pass the appropriate server name(s) for the
 * SPN to the {@link SaslClient}. It is deemed to fail. Note, that host name canocalization might
 * sound reasonable within the {@code SaslClient}, but this is deemed to fail too for two reasons:
 * First, the {@code SaslClient} will receive an arbitrary IP address without knowing whether the
 * LDAP client socket will use the same one. You will have a service ticket issued for another host
 * and your authentication will fail. Second, most Kerberos implementations rely on reverse DNS
 * records, but Microsoft's Active Directory concept does not care about reverse DNS, it does not
 * canonicalize host names by default and there is no guarantee, that reverse DNS is set up
 * properly. Some environments do not even have control over the reverse DNS zone ({@code PTR}
 * records). Using {@code throw} will not make it any better because the referral URL returned by
 * {@link ReferralException#getReferralInfo()} cannot be changed with the calculated value(s) from
 * DNS. {@link ReferralException#getReferralContext()} will unconditionally reuse that value. The
 * only way (theoretically) to achieve this is to construct an {@link InitialDirContext} with the
 * new URL manually and work with it appropriately. Though, this approach has not been evaluated and
 * at this time and won't be implemented. (Changing the URLs manually in the debugger makes it work
 * actually)
 * <p>
 * <em>How to work around this issue?</em> There are several ways depending on your setup: Use the
 * Global Catalog (port 3268) with
 * <ul>
 * <li>a single forest and set referrals to {@code ignore}, or</li>
 * <li>multiple forests and set referrals to either
 * <ul>
 * <li>{@code follow} or {@code throw} with a {@link DirContextSource} in your home forest, patch
 * {@code com.sun.jndi.ldap.LdapCtxFactory} to properly resolve DNS domain names to host names and
 * prepend it to the boot classpath and all referrals will be cleanly resolved, or</li>
 * <li>{@code ignore} with multiple {@code DirContextSources}, and create a
 * {@link CombinedActiveDirectoryRealm} with one {@code ActiveDirectoryRealm} per forest.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * You will then have the principal properly looked up in the Active Directory.
 * <p>
 * This issue is also documented on <a href="http://stackoverflow.com/q/25436410/696632">Stack
 * Overflow</a>. Additionally,
 * <a href="https://technet.microsoft.com/en-us/library/cc759550%28v=ws.10%29.aspx">How DNS Support
 * for Active Directory Works</a> is a good read on the DNS topic as well as
 * <a href="https://technet.microsoft.com/en-us/library/cc978012.aspx">Global Catalog and LDAP
 * Searches</a> and <a href="https://technet.microsoft.com/en-us/library/cc978014.aspx">LDAP
 * Referrals</a>.
 * <p>
 * <strong>Note:</strong> always remember, referrals incur an amplification in time and space and
 * make the entire process slower.
 *
 * @see ActiveDirectoryPrincipal
 * @version $Id$
 */
public class ActiveDirectoryRealm extends GSSRealmBase {

	private static final UsernameSearchMapper[] USERNAME_SEARCH_MAPPERS = {
			new SamAccountNameRfc2247Mapper(), new UserPrincipalNameSearchMapper() };

	private static final String[] DEFAULT_USER_ATTRIBUTES = new String[] { "userAccountControl",
			"memberOf", "objectSid;binary" };

	private static final String[] DEFAULT_ROLE_ATTRIBUTES = new String[] { "groupType",
			"objectSid;binary", "sIDHistory;binary" };

	protected boolean localDirContextSource;
	protected String dirContextSourceName;
	protected String[] additionalAttributes;

	/**
	 * Descriptive information about this Realm implementation.
	 */
	protected static final String name = "ActiveDirectoryRealm";

	/**
	 * Sets whether the {@code DirContextSource} is locally ({@code context.xml} defined or globally
	 * {@code server.xml}.
	 *
	 * @param localDirContextSource
	 *            the local directory context source indication
	 */
	public void setLocalDirContextSource(boolean localDirContextSource) {
		this.localDirContextSource = localDirContextSource;
	}

	/**
	 * Sets the name of the {@code DirContextSource}
	 *
	 * @param dirContextSourceName
	 *            the directory context source name
	 */
	public void setDirContextSourceName(String dirContextSourceName) {
		this.dirContextSourceName = dirContextSourceName;
	}

	/**
	 * Sets a comma-separated list of Active Directory attributes retreived and stored for the user
	 * principal.
	 *
	 * @param additionalAttributes
	 *            the additional attributes.
	 */
	public void setAdditionalAttributes(String additionalAttributes) {
		this.additionalAttributes = additionalAttributes.split(",");
	}

	@Override
	protected String getName() {
		return name;
	}

	@Override
	public Principal authenticate(GSSName gssName, GSSCredential gssCredential) {
		return getPrincipal(gssName, gssCredential);
	}

	@Override
	public Principal authenticate(GSSContext gssContext, boolean storeCreds) {
		if (gssContext.isEstablished()) {
			GSSName gssName = null;
			try {
				gssName = gssContext.getSrcName();
			} catch (GSSException e) {
				logger.error(sm.getString("activeDirectoryRealm.gssNameFailed"), e);
			}

			if (gssName != null) {
				GSSCredential gssCredential = null;
				if (storeCreds) {
					if (gssContext.getCredDelegState()) {
						try {
							gssCredential = gssContext.getDelegCred();
						} catch (GSSException e) {
							logger.warn(sm.getString(
									"activeDirectoryRealm.delegatedCredentialFailed", gssName), e);
						}
					} else {
						if (logger.isDebugEnabled())
							logger.debug(sm.getString("activeDirectoryRealm.credentialNotDelegable",
									gssName));
					}
				}

				return getPrincipal(gssName, gssCredential);
			}
		} else
			logger.error(sm.getString("activeDirectoryRealm.securityContextNotEstablished"));

		return null;
	}

	@Override
	protected Principal getPrincipal(GSSName gssName, GSSCredential gssCredential) {
		if (gssName.isAnonymous())
			return new ActiveDirectoryPrincipal(gssName, Sid.ANONYMOUS_SID, gssCredential);

		DirContext context = open();
		if (context == null)
			return null;

		try {
			User user = getUser(context, gssName);

			if (user != null) {
				List<String> roles = getRoles(context, user);

				return new ActiveDirectoryPrincipal(gssName, user.getSid(), roles, gssCredential,
						user.getAdditionalAttributes());
			}
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.principalSearchFailed", gssName), e);
		} finally {
			close(context);
		}

		return null;
	}

	@Override
	protected boolean hasRoleInternal(Principal principal, String role) {
		if (!(principal instanceof ActiveDirectoryPrincipal))
			return false;

		ActiveDirectoryPrincipal adp = (ActiveDirectoryPrincipal) principal;

		boolean result;
		if (getContainer() instanceof Context) {
			Context context = (Context) getContainer();
			result = adp.hasRole(context.findRoleMapping(role));
		} else
			result = adp.hasRole(role);

		return result;
	}

	protected DirContext open() {
		try {
			javax.naming.Context context = null;

			if (localDirContextSource) {
				context = ContextBindings.getClassLoader();
				context = (javax.naming.Context) context.lookup("comp/env");
			} else {
				Server server = getServer();
				context = server.getGlobalNamingContext();
			}

			DirContextSource contextSource = (DirContextSource) context
					.lookup(dirContextSourceName);
			return contextSource.getDirContext();
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.open"), e);
		}

		return null;
	}

	protected void close(DirContext context) {
		if (context == null)
			return;

		try {
			context.close();
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.close"), e);
		}
	}

	protected void close(NamingEnumeration<?> results) {
		if (results == null)
			return;

		try {
			results.close();
		} catch (NamingException e) {
			; // swallow
		}
	}

	@Override
	protected void startInternal() throws LifecycleException {
		super.startInternal();

		DirContext context = open();
		if (context == null)
			return;

		try {
			String referral = (String) context.getEnvironment().get(DirContext.REFERRAL);

			if ("follow".equals(referral))
				logger.warn(sm.getString("activeDirectoryRealm.referralFollow"));
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.environmentFailed"), e);
		} finally {
			close(context);
		}
	}

	@Override
	public String[] getRoles(Principal principal) {
		if (principal instanceof ActiveDirectoryPrincipal) {
			return ((ActiveDirectoryPrincipal) principal).getRoles();
		}

		String className = principal.getClass().getName();
		throw new IllegalStateException(sm.getString("activeDirectoryRealm.cannotGetRoles",
				principal.getName(), className));
	}

	protected User getUser(DirContext context, GSSName gssName) throws NamingException {

		String[] attributes = DEFAULT_USER_ATTRIBUTES;

		if (additionalAttributes != null && additionalAttributes.length > 0) {
			attributes = new String[DEFAULT_USER_ATTRIBUTES.length + additionalAttributes.length];
			System.arraycopy(DEFAULT_USER_ATTRIBUTES, 0, attributes, 0,
					DEFAULT_USER_ATTRIBUTES.length);
			System.arraycopy(additionalAttributes, 0, attributes, DEFAULT_USER_ATTRIBUTES.length,
					additionalAttributes.length);
		}

		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchCtls.setReturningAttributes(attributes);

		// Query for user and machine accounts only
		String searchFilterPattern = "(&(|(sAMAccountType=805306368)(sAMAccountType=805306369))(%s={0}))";

		String searchFilter;
		Name searchBase = null;
		String searchAttributeName;
		String searchAttributeValue;

		MappedValues mappedValues;
		NamingEnumeration<SearchResult> results = null;
		for (UsernameSearchMapper mapper : USERNAME_SEARCH_MAPPERS) {
			String mapperClassName = mapper.getClass().getSimpleName();
			mappedValues = mapper.map(context, gssName);

			searchBase = getRelativeName(context, mappedValues.getSearchBase());
			searchAttributeName = mappedValues.getSearchAttributeName();
			searchAttributeValue = mappedValues.getSearchUsername();

			searchFilter = String.format(searchFilterPattern, searchAttributeName);

			if (logger.isDebugEnabled())
				logger.debug(sm.getString("activeDirectoryRealm.usernameSearch",
						searchAttributeValue, searchBase, searchAttributeName, mapperClassName));

			try {
				results = context.search(searchBase, searchFilter,
						new Object[] { searchAttributeValue }, searchCtls);
			} catch (ReferralException e) {
				logger.warn(sm.getString("activeDirectoryRealm.user.referralException",
						mapperClassName, e.getRemainingName(), e.getReferralInfo()));

				continue;
			}

			try {
				if (!results.hasMore()) {
					if (logger.isDebugEnabled())
						logger.debug(sm.getString("activeDirectoryRealm.userNotMapped", gssName,
								mapperClassName));

					close(results);
					results = null;
				} else
					break;
			} catch (PartialResultException e) {
				logger.debug(sm.getString("activeDirectoryRealm.user.partialResultException",
						mapperClassName, e.getRemainingName()));

				close(results);
				results = null;
			}
		}

		if (results == null) {
			logger.debug(sm.getString("activeDirectoryRealm.userNotFound", gssName));

			return null;
		}

		SearchResult result = results.next();

		if (results.hasMore()) {
			logger.error(sm.getString("activeDirectoryRealm.duplicateUser", gssName));

			close(results);
			return null;
		}

		Attributes userAttributes = result.getAttributes();

		int userAccountControl = Integer
				.parseInt((String) userAttributes.get("userAccountControl").get());

		// Do not allow disabled accounts (UF_ACCOUNT_DISABLE)
		if ((userAccountControl & 0x02) == 0x02) {
			logger.warn(sm.getString("activeDirectoryRealm.userFoundButDisabled", gssName));

			close(results);
			return null;
		}

		Name dn = getDistinguishedName(context, searchBase, result);
		byte[] sidBytes = (byte[]) userAttributes.get("objectSid;binary").get();
		Sid sid = new Sid(sidBytes);

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.userFound", gssName, dn, sid));

		Attribute memberOfAttr = userAttributes.get("memberOf");

		List<String> roles = new LinkedList<String>();

		if (memberOfAttr != null && memberOfAttr.size() > 0) {
			NamingEnumeration<?> memberOfValues = memberOfAttr.getAll();

			while (memberOfValues.hasMore())
				roles.add((String) memberOfValues.next());

			close(memberOfValues);
		}

		Map<String, Object> additionalAttributesMap = Collections.emptyMap();

		if (additionalAttributes != null && additionalAttributes.length > 0) {
			additionalAttributesMap = new HashMap<String, Object>();

			for (String addAttr : additionalAttributes) {
				Attribute attr = userAttributes.get(addAttr);

				if (attr != null && attr.size() > 0) {
					if (attr.size() > 1) {
						List<Object> attrList = new ArrayList<Object>(attr.size());
						NamingEnumeration<?> attrEnum = attr.getAll();

						while (attrEnum.hasMore())
							attrList.add(attrEnum.next());

						close(attrEnum);

						additionalAttributesMap.put(addAttr,
								Collections.unmodifiableList(attrList));
					} else
						additionalAttributesMap.put(addAttr, attr.get());
				}
			}
		}

		close(results);
		return new User(gssName, sid, roles, additionalAttributesMap);
	}

	protected List<String> getRoles(DirContext context, User user) throws NamingException {

		List<String> roles = new LinkedList<String>();

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.retrievingRoles", user.getGssName()));

		for (String role : user.getRoles()) {
			Name roleRdn = getRelativeName(context, role);

			Attributes roleAttributes = null;
			try {
				roleAttributes = context.getAttributes(roleRdn, DEFAULT_ROLE_ATTRIBUTES);
			} catch (ReferralException e) {
				logger.warn(sm.getString("activeDirectoryRealm.role.referralException", role,
						e.getRemainingName(), e.getReferralInfo()));

				continue;
			} catch (PartialResultException e) {
				logger.debug(sm.getString("activeDirectoryRealm.role.partialResultException", role,
						e.getRemainingName()));

				continue;
			}

			int groupType = Integer.parseInt((String) roleAttributes.get("groupType").get());

			// Skip distribution groups, i.e., we want security-enabled groups only
			// (ADS_GROUP_TYPE_SECURITY_ENABLED)
			if ((groupType & Integer.MIN_VALUE) == 0) {
				if (logger.isTraceEnabled())
					logger.trace(
							sm.getString("activeDirectoryRealm.skippingDistributionRole", role));

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

				close(sidHistoryEnum);
			}

			roles.add(sidString);
			roles.addAll(sidHistoryStrings);

			if (logger.isTraceEnabled()) {
				if (sidHistoryStrings.isEmpty())
					logger.trace(sm.getString("activeDirectoryRealm.foundRoleConverted", role,
							sidString));
				else
					logger.trace(
							sm.getString("activeDirectoryRealm.foundRoleConverted.withSidHistory",
									role, sidString, sidHistoryStrings));
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
	 * @param baseName
	 *            The base DN
	 * @param result
	 *            The search result
	 * @return String containing the distinguished name
	 * @throws NamingException
	 *             if DN cannot be build
	 */
	protected Name getDistinguishedName(DirContext context, Name baseName, SearchResult result)
			throws NamingException {
		// Get the entry's distinguished name. For relative results, this means
		// we need to composite a name with the base name, the context name, and
		// the result name. For non-relative names, use the returned name.
		String resultName = result.getName();
		if (result.isRelative()) {
			NameParser parser = context.getNameParser(StringUtils.EMPTY);
			Name contextName = parser.parse(context.getNameInNamespace());

			// Bugzilla 32269
			Name entryName = parser.parse(new CompositeName(resultName).get(0));

			Name name = contextName.addAll(baseName);
			return name.addAll(entryName);
		} else {
			String absoluteName = result.getName();
			try {
				// Normalize the name by running it through the name parser.
				NameParser parser = context.getNameParser(StringUtils.EMPTY);
				URI userNameUri = new URI(resultName);
				String pathComponent = userNameUri.getPath();
				// Should not ever have an empty path component, since that is /{DN}
				if (pathComponent.length() < 1) {
					throw new InvalidNameException(
							sm.getString("activeDirectoryRealm.unparseableName", absoluteName));
				}
				return parser.parse(pathComponent.substring(1));
			} catch (URISyntaxException e) {
				throw new InvalidNameException(
						sm.getString("activeDirectoryRealm.unparseableName", absoluteName));
			}
		}
	}

	protected Name getRelativeName(DirContext context, String distinguishedName)
			throws NamingException {

		NameParser parser = context.getNameParser(StringUtils.EMPTY);
		LdapName nameInNamespace = (LdapName) parser.parse(context.getNameInNamespace());
		LdapName name = (LdapName) parser.parse(distinguishedName);

		Rdn nameRdn;
		Rdn nameInNamespaceRdn;

		while (Math.min(name.size(), nameInNamespace.size()) != 0) {
			nameRdn = name.getRdn(0);
			nameInNamespaceRdn = nameInNamespace.getRdn(0);
			if (nameRdn.equals(nameInNamespaceRdn)) {
				name.remove(0);
				nameInNamespace.remove(0);
			} else
				break;
		}

		int innerPosn;
		while (Math.min(name.size(), nameInNamespace.size()) != 0) {
			innerPosn = nameInNamespace.size() - 1;
			nameRdn = name.getRdn(0);
			nameInNamespaceRdn = nameInNamespace.getRdn(innerPosn);
			if (nameRdn.equals(nameInNamespaceRdn)) {
				name.remove(0);
				nameInNamespace.remove(innerPosn);
			} else
				break;
		}

		return name;
	}

	protected static class User {
		private final GSSName gssName;
		private final Sid sid;
		private final List<String> roles;
		private final Map<String, Object> additionalAttributes;

		public User(GSSName gssName, Sid sid, List<String> roles,
				Map<String, Object> additionalAttributes) {
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
