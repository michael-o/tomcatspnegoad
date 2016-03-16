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
import javax.security.sasl.SaslClient;

import net.sf.michaelo.dirctxsrc.DirContextSource;
import net.sf.michaelo.tomcat.realm.mapper.SamAccountNameRfc2247Mapper;
import net.sf.michaelo.tomcat.realm.mapper.UserPrincipalNameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper.MappedValues;
import net.sf.michaelo.tomcat.utils.LdapUtils;

import org.apache.catalina.Context;
import org.apache.catalina.realm.CombinedRealm;
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
 * {@code byte[]}, ordinary attributes will be stored as {@code String}. If an attribute is
 * multivalued, it will be stored as {@code List}.</li>
 * <li>{@code storeDelegatedCredential}: Store the client's (initiator's) delegated credential in
 * the user principal (optional). Valid values are {@code true}, {@code false}. Default value is
 * {@code false}.</li>
 * </ul>
 * <p>
 * By default the SIDs ({@code objectSid} and {@code sIDHistory}) of the Active Directory security
 * groups will be retreived.
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
 * {@link ReferralException} but avoid to follow the referral(s) manually for several reasons and
 * will continue with the process. Following referrals automatically is a completely opaque
 * operation to the application, the {@code ReferralException} is handled internally and referral
 * contexts are queried and closed. Unfortunately, Oracle's LDAP implementation is not able to
 * handle this properly and only Oracle can fix this shortcoming.
 * <p>
 * <em>What is the shortcoming and how can it be solved?</em> Microsoft takes a very sophisticated
 * approach on not to rely on host names because servers can be provisioned and decommissioned any
 * time. Instead, they heavily rely on DNS domain names and DNS SRV records at runtime. I.e., the
 * referral URL does not contain a host name, but only a DNS domain name. While you can connect to
 * the service with this name, you cannot easily authenticate against it with Kerberos because one
 * cannot bind the same SPN {@code ldap/<dnsDomainName>@<REALM>}, e.g.,
 * {@code ldap/example.com@EXAMPLE.COM} to more than one account. If you try authenticate anyway,
 * you will receive a "Server not found in kerberos database (7)" error. Therefore, one has to
 * perform a DNS SRV query ({@code _ldap._tcp.<dnsDomainName>}) to test whether this name is a host
 * name or a DNS domain name served by one or more machines. If it turns out to be a DNS domain
 * name, you have to select one arbitrary target host from the query response, construct a special
 * SPN {@code ldap/<targetHost>/<dnsDomainName>@<REALM>} or a regular one {@code ldap/<targetHost>@
 * <REALM>}, obtain a service ticket for and connect to that target host. If it is a regular host
 * name, which is not the usual case with Active Directory, Oracle's internal implementation will
 * behave correctly.<br>
 * The {@code follow} implementation cannot be made to work because there is no way to tell the
 * internal classes to perform this DNS SRV query and pass the appropriate server name(s) for the
 * SPN to the {@link SaslClient}. It is deemed to fail. Note, that host name canocalization might
 * sound reasonable within the {@code SaslClient}, but this is deemed to fail too for two reasons.
 * First, the {@code SaslClient} will receive an arbitrary IP address without knowing whether the
 * LDAP client socket will use the same one. You will have a service ticket issued for another host
 * and your authentication will fail. Second, most Kerberos implementations rely on reverse DNS
 * records, but Microsoft's SSPI Kerberos provider does not care about reverse DNS, it does not
 * canonicalize host names by default and there is no guarantee, that reverse DNS is set up
 * properly. Using {@code throw} will not make it any better because the referral URL returned by
 * {@link ReferralException#getReferralInfo()} cannot be changed with the calculated values from
 * DNS. {@link ReferralException#getReferralContext()} will unconditionally reuse that value. The
 * only way (theoretically) to achieve this is to construct an {@link InitialDirContext} with the
 * new URL manually and work with it appropriately. Though, this approach has not been evaluated and
 * at this time, it won't be implemented. (Changing the URLs manually in the debugger makes it work
 * actually)
 * <p>
 * <em>How to work around this issue?</em> Use the global catalog (port 3268) as much as you can. If
 * this won't help and you know your target forests upfront, you can set up a {@link CombinedRealm},
 * configure nested realms one per each forest with {@code ignore} and let the principal iterate
 * over all of them until it hits the target forest. You will then have the client properly looked
 * up in the Active Directory.
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
public class ActiveDirectoryRealm extends GSSRealmBase<DirContextSource> {

	private static final UsernameSearchMapper[] USERNAME_SEARCH_MAPPERS = {
			new SamAccountNameRfc2247Mapper(), new UserPrincipalNameSearchMapper() };

	private static final String[] DEFAULT_ATTRIBUTES = new String[] { "userAccountControl",
			"memberOf", "objectSid;binary" };

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
	public void init() {
		super.init();

		DirContextSource dirContextSource = null;
		try {
			dirContextSource = lookupResource();
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryealm.lookupFailed", resourceName), e);

			return;
		}
		DirContext context = null;
		try {
			context = dirContextSource.getDirContext();
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.obtainFailed", resourceName), e);
			return;
		}

		try {
			String referral = (String) context.getEnvironment().get(DirContext.REFERRAL);

			if ("follow".equals(referral))
				logger.warn(sm.getString("activeDirectoryRealm.referralFollow"));
			else if ("throw".equals(referral))
				logger.warn(sm.getString("activeDirectoryRealm.referralThrow"));
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.environmentFailed"), e);
		} finally {
			LdapUtils.close(context);
		}
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

		if(gssName.isAnonymous())
			return new ActiveDirectoryPrincipal(gssName, Sid.ANONYMOUS_SID, delegatedCredential);

		Principal principal = null;
		try {
			User user = getUser(context, gssName);

			if (user != null) {
				if(user.getSid().equals(Sid.NULL_SID))
					principal = new ActiveDirectoryPrincipal(gssName, user.getSid(), delegatedCredential);
				else {
					List<String> roles = getRoles(context, user);

					principal = new ActiveDirectoryPrincipal(gssName, user.getSid(), delegatedCredential,
							roles, user.getAdditionalAttributes());
				}
			}
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.principalSearchFailed", gssName), e);
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
			} catch(ReferralException e) {
				logger.warn(
						sm.getString("activeDirectoryRealm.user.referralException", mapperClassName,
								e.getRemainingName(), e.getReferralInfo()));

				continue;
			}

			try {
				if (!results.hasMore()) {
					if (logger.isDebugEnabled())
						logger.debug(sm.getString("activeDirectoryRealm.userNotMapped", gssName,
								mapperClassName));

					LdapUtils.close(results);
					results = null;
				} else
					break;
			} catch(PartialResultException e) {
				logger.debug(
						sm.getString("activeDirectoryRealm.user.partialResultException", mapperClassName,
								e.getRemainingName()));

				LdapUtils.close(results);
				results = null;
			}
		}

		if (results == null) {
			logger.info(sm.getString("activeDirectoryRealm.userNotFound", gssName));

			return new User(gssName, Sid.NULL_SID, null, null);
		}

		SearchResult result = results.next();

		if (results.hasMore()) {
			logger.error(sm.getString("activeDirectoryRealm.duplicateUser", gssName));

			LdapUtils.close(results);
			return null;
		}

		Attributes userAttributes = result.getAttributes();

		int userAccountControl = Integer.parseInt((String) userAttributes.get("userAccountControl")
				.get());

		// Do not allow disabled accounts (UF_ACCOUNT_DISABLE)
		if((userAccountControl & 0x2) == 0x2) {
			logger.warn(sm.getString("activeDirectoryRealm.userFoundButDisabled", gssName));

			LdapUtils.close(results);
			return null;
		}

		LdapName dn = getDistinguishedName(context, searchBase, result);
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

			LdapUtils.close(memberOfValues);
		}

		Map<String, Object> additionalAttributesMap = Collections.emptyMap();

		if(ArrayUtils.isNotEmpty(additionalAttributes)) {
			additionalAttributesMap = new HashMap<String, Object>();

			for(String addAttr : additionalAttributes) {
				Attribute attr = userAttributes.get(addAttr);

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

		LdapUtils.close(results);
		return new User(gssName, sid, roles, additionalAttributesMap);
	}

	protected List<String> getRoles(DirContext context, User user) throws NamingException {

		List<String> roles = new LinkedList<String>();

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.retrievingRoles", user.getGssName()));

		for (String role : user.getRoles()) {
			String roleRdn = getRelativeName(context, role);

			Attributes roleAttributes = null;
			try {
				roleAttributes = context.getAttributes(roleRdn, new String[] { "groupType",
						"objectSid;binary", "sIDHistory;binary" });
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
	 * @throws NamingException
	 *             if DN cannot be build
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
