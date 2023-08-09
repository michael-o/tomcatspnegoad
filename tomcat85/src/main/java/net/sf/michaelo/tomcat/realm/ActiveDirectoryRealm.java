/*
 * Copyright 2013–2023 Michael Osipov
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
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import javax.naming.CommunicationException;
import javax.naming.CompositeName;
import javax.naming.InvalidNameException;
import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.ReferralException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.ManageReferralControl;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import net.sf.michaelo.dirctxsrc.DirContextSource;
import net.sf.michaelo.tomcat.realm.asn1.OtherNameAsn1Parser;
import net.sf.michaelo.tomcat.realm.asn1.OtherNameParseResult;
import net.sf.michaelo.tomcat.realm.mapper.SamAccountNameRfc2247Mapper;
import net.sf.michaelo.tomcat.realm.mapper.UserPrincipalNameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper.MappedValues;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Server;
import org.apache.catalina.realm.CombinedRealm;
import org.apache.commons.lang3.StringUtils;
import org.apache.naming.ContextBindings;
import org.apache.tomcat.util.codec.binary.Base64;
import org.apache.tomcat.util.collections.SynchronizedStack;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * A realm which retrieves <em>already authenticated</em> users from Active Directory.
 *
 * <h2 id="configuration">Configuration</h2> Following options can be configured:
 * <ul>
 * <li>{@code dirContextSourceName}: the name of the {@link DirContextSource} in JNDI with which
 * principals will be retrieved.</li>
 * <li>{@code localDirContextSource}: whether this {@code DirContextSource} is locally configured in
 * the {@code context.xml} or globally configured in the {@code server.xml} (optional). Default
 * value is {@code false}.</li>
 * <li>{@code roleFormats}: comma-separated list of role formats to be applied to user security
 * groups. The following values are possible: {@code sid} retrieves the {@code objectSid} and
 * {@code sIDHistory} attribute values, {@code name} retrieves the {@code msDS-PrincipalName} attribute
 * value representing the down-level logon name format: <code>{netbiosDomain}\{samAccountName}</code>,
 * and {@code nameEx} retrieves the {@code distinguishedName} and {@code sAMAccountName} attribute
 * values and converts the DC RDNs from the DN to the Kerberos realm and appends the
 * {@code sAMAccountName} (reversed RFC 2247) with format <code>{realm}\{samAccountName}</code>.
 * Default is {@code sid}.</li>
 * <li>{@code prependRoleFormat}: whether the role format is prepended to the role as
 * <code>{roleFormat}:{role}</code>. Default is {@code false}.
 * <li>{@code additionalAttributes}: comma-separated list of attributes to be retrieved for the
 * principal. Binary attributes must end with {@code ;binary} and will be stored as {@code byte[]},
 * ordinary attributes will be stored as {@code String}. If an attribute is multivalued, it will be
 * stored as {@code List}.</li>
 * <li>{@code connectionPoolSize}: the maximum amount of directory server connections the pool will
 * hold. Default is zero which means no connections will be pooled.</li>
 * <li>{@code maxIdleTime}: the maximum amount of time in milliseconds a directory server connection
 * should remain idle before it is closed. Default value is 15 minutes.</li>
 * </ul>
 * <h2>Connection Pooling</h2> This realm offers a poor man's directory server connection pooling
 * which can drastically improve access performance for non-session (stateless) applications. It
 * utilizes a LIFO structure based on {@link SynchronizedStack}. No background thread is managing
 * the connections. They are acquired, validated, eventually closed and opened when
 * {@link #getPrincipal(GSSName, GSSCredential)} is invoked. Validation involves a minimal and
 * limited query with at most 500 ms of wait time just to verify the connection is alive and
 * healthy. If this query fails, the connection is closed immediately. If the amount of requested
 * connections exceeds the ones available in the pool, new ones are opened and pushed onto the pool.
 * If the pool does not accept any addtional connections they are closed immediately.
 * <p>
 * <strong>Note:</strong> This connection pool feature has to be explicitly enabled by setting
 * {@code connectionPoolSize} to greater than zero.
 *
 * <h2 id="on-usernames">On Usernames</h2>
 * This realm processes supplied usernames with different types.
 * <h3>Supported Types</h3> Only a subset of username types are accepted in contrast to
 * other realm implementations. Namely, this realm must know what type is passed to properly map
 * it into Active Directory search space with a {@link UsernameSearchMapper} implementation.
 * The supported username types are:
 * <ul>
 * <li>{@link GSSName} by inspecting the string name type,</li>
 * <li>{@link X509Certificate} by extracting the {@code SAN:otherName} field and matching for
 * MS UPN type id (1.3.6.1.4.1.311.20.2.3).</li>
 * </ul>
 * <p>
 * <strong>Note:</strong> Both types represent <em>already authenticated</em> users by means of a
 * GSS and/or TLScontext.
 *<h3>Canonicalization</h3>
 * This realm will always try to canonicalize a given username type to a real {@link GSSName}
 * with the string name type of {@code KRB5_NT_PRINCIPAL} (1.2.840.113554.1.2.2.1) similar to
 * the {@code canonicalize} flag in the <a href="https://web.mit.edu/kerberos/krb5-1.19/doc/admin/conf_files/krb5_conf.html">
 * {@code krb5.conf}</a> file. This makes the final {@link GSSName} fully usable in subsequent
 * GSS-API calls.
 *
 * <h2 id="referral-handling">Referral Handling</h2> Active Directory uses two type of responses
 * when it cannot complete a search request: referrals and search result references. Both are
 * different in nature, read more about them <a href="https://documentation.avaya.com/en-US/bundle/DeployingAvayaDeviceServices_R8.1.4/page/LDAP_Search_Results_and_Referrals.html">here</a>.
 * For this section I will use the term <i>referral</i> for both types synomously as does the
 * <a href="https://docs.oracle.com/javase/jndi/tutorial/ldap/referral/jndi.html">JNDI/LDAP Provider documentation</a>.
 * <br>
 * When working with the default LDAP ports (not
 * GC) or in a multi-forest environment, it is highly likely to receive referrals (either
 * subordinate or cross) during a search or lookup. Sun's JNDI/LDAP Provider takes the following
 * approach to handle referrals with the {@code java.naming.referral} property and its values:
 * {@code ignore}, {@code throw}, and {@code follow}. You can ignore referrals altogether, but
 * the provider will still signal a {@link PartialResultException} when a {@link NamingEnumeration}
 * is iterated. The reason is because it adds a {@link ManageReferralControl} when {@code ignore}
 * is set and assumes that the target server will ignore referrals, but this is a misconception
 * in this provider implementation, see
 * <a href="https://openldap-software.0penldap.narkive.com/cuImLMRw/managedsait#post2">here</a>
 * and <a href="https://bugs.openjdk.java.net/browse/JDK-5109452">here</a>. It is also unclear
 * whether Microsoft Active Directory supports this control.
 * <br>
 * This realm will catch this exception and continue to process the enumeration. If the {@code DirContextSource}
 * is set to {@code throw}, this realm will catch the {@link ReferralException} also, but avoid
 * following referrals manually (for several reasons) and will continue with the process.
 * Following referrals automatically is a completely opaque operation to the application, no
 * {@code ReferralException} is thrown, but the referrals are handled internally and referral
 * contexts are queried and closed. If you choose to {@code follow} referrals you <strong>must</strong>
 * use my <a href="https://michael-o.github.io/activedirectory-dns-locator/">Active Directory DNS Locator</a>
 * otherwise the queries <strong>will</strong> fail and you will suffer from
 * <a href="https://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8161361">JDK-8161361</a> and
 * <a href="https://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8160768">JDK-8160768</a>!
 * <p>
 * <em>Why do you need to use my Active Directory DNS Locator?</em> Microsoft takes a very
 * sophisticated approach on not to rely on hostnames because servers can be provisioned and
 * decommissioned any time. Instead, they heavily rely on DNS domain names and DNS SRV records
 * at runtime. I.e., an initial or a referral URL does not contain a hostname, but only a domain
 * name. While you can connect to the service with this name, you cannot easily authenticate
 * against it with Kerberos because one cannot bind the same SPN {@code ldap/<dnsDomainName>@<REALM>},
 * e.g., {@code ldap/example.com@EXAMPLE.COM} to more than one account. If you try authenticate
 * anyway, you will receive a "Server not found in Kerberos database (7)" error. Therefore, one has
 * to perform a DNS SRV query ({@code _ldap._tcp.<dnsDomainName>}) to test whether this name is a
 * hostname or a domain name served by one or more servers. If it turns out to be a domain name,
 * you have to select one target host from the query response (according to RFC 2782), construct
 * a domain-based SPN {@code ldap/<targetHost>/<dnsDomainName>@<REALM>} or a host-based
 * one {@code ldap/<targetHost>@<REALM>}, obtain a service ticket for and connect to that target
 * host.
 * <p>
 * <em>How to handle referrals?</em> There are several ways depending on your setup: Use the
 * Global Catalog (port 3268) with a single forest and set referrals to {@code ignore}, or
 * with multiple forests and set referrals to either
 * <ul>
 * <li>{@code follow} with a {@link DirContextSource} in your home forest and use my Active
 * Directory DNS Locator, or</li>
 * <li>{@code ignore} with multiple {@code DirContextSources}, and create a {@link CombinedRealm}
 * with one {@code ActiveDirectoryRealm} per forest.</li>
 * </ul>
 *<p>
 * You will then have the principal properly looked up in Active Directory.
 * <p>
 * Further references:
 * <a href="https://technet.microsoft.com/en-us/library/cc759550%28v=ws.10%29.aspx">How DNS Support
 * for Active Directory Works</a> is a good read on the DNS topic as well as
 * <a href="https://technet.microsoft.com/en-us/library/cc978012.aspx">Global Catalog and LDAP
 * Searches</a> and <a href="https://technet.microsoft.com/en-us/library/cc978014.aspx">LDAP
 * Referrals</a>.
 * <p>
 * <strong>Note:</strong> Always remember, referrals incur an amplification in time and space and
 * make the entire process slower.
 *
 * @see ActiveDirectoryPrincipal
 */
public class ActiveDirectoryRealm extends ActiveDirectoryRealmBase {

	// A mere holder class for directory server connections
	protected static class DirContextConnection {
		protected String id;
		protected long lastBorrowTime;
		protected DirContext context;
	}

	private static final AtomicLong COUNT = new AtomicLong(0);

	// 1.3.6.1.4.1.311.20.2.3
	private static final byte[] MS_UPN_OID_BYTES = { (byte) 0x2B, (byte) 0x06, (byte) 0x01, (byte) 0x04, (byte) 0x01,
			(byte) 0x82, (byte) 0x37, (byte) 0x14, (byte) 0x02, (byte) 0x03 };

	private final static Oid MS_UPN;
	private final static Oid KRB5_NT_PRINCIPAL;

	private final static Map<String, String> X500_PRINCIPAL_OID_MAP = new HashMap<String, String>();

	private static final UsernameSearchMapper[] USERNAME_SEARCH_MAPPERS = {
			new SamAccountNameRfc2247Mapper(), new UserPrincipalNameSearchMapper() };

	private static final String[] DEFAULT_USER_ATTRIBUTES = new String[] { "userAccountControl",
			"memberOf", "objectSid;binary", "sAMAccountName" };

	private static final String[] DEFAULT_ROLE_ATTRIBUTES = new String[] { "groupType" };

	private static final String DEFAULT_ROLE_FORMAT = "sid";

	private static final Map<String, String[]> ROLE_FORMAT_ATTRIBUTES = new HashMap<>();

	static {
		try {
			MS_UPN = new Oid("1.3.6.1.4.1.311.20.2.3");
		} catch (GSSException e) {
			throw new IllegalStateException("Failed to create OID for MS_UPN");
		}

		try {
			KRB5_NT_PRINCIPAL = new Oid("1.2.840.113554.1.2.2.1");
		} catch (GSSException e) {
			throw new IllegalStateException("Failed to create OID for KRB5_NT_PRINCIPAL");
		}

		X500_PRINCIPAL_OID_MAP.put("1.2.840.113549.1.9.1", "emailAddress");
		X500_PRINCIPAL_OID_MAP.put("2.5.4.5", "serialNumber");
		// surname
		X500_PRINCIPAL_OID_MAP.put("2.5.4.4", "SN");
		// givenName
		X500_PRINCIPAL_OID_MAP.put("2.5.4.42", "GN");

		ROLE_FORMAT_ATTRIBUTES.put("sid", new String[] { "objectSid;binary", "sIDHistory;binary" });
		ROLE_FORMAT_ATTRIBUTES.put("name", new String [] { "msDS-PrincipalName" } );
		ROLE_FORMAT_ATTRIBUTES.put("nameEx", new String [] { "distinguishedName", "sAMAccountName" } );
	}

	protected boolean localDirContextSource;
	protected String dirContextSourceName;

	protected String[] attributes;
	protected String[] additionalAttributes;

	protected String[] roleFormats;
	protected String[] roleAttributes;

	protected boolean prependRoleFormat;

	protected int connectionPoolSize = 0;
	protected long maxIdleTime = 900_000L;

	// Poor man's connection pool
	protected SynchronizedStack<DirContextConnection> connectionPool;

	/**
	 * Descriptive information about this Realm implementation.
	 */
	protected static final String name = "ActiveDirectoryRealm";

	protected static String getNextConnectionId() {
		return String.format("conn-%06d", COUNT.incrementAndGet());
	}

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
	 *            the additional attributes
	 */
	public void setAdditionalAttributes(String additionalAttributes) {
		this.additionalAttributes = additionalAttributes.split(",");

		this.attributes = new String[DEFAULT_USER_ATTRIBUTES.length + this.additionalAttributes.length];
			System.arraycopy(DEFAULT_USER_ATTRIBUTES, 0, this.attributes, 0,
					DEFAULT_USER_ATTRIBUTES.length);
			System.arraycopy(this.additionalAttributes, 0, this.attributes, DEFAULT_USER_ATTRIBUTES.length,
					this.additionalAttributes.length);
	}

	/**
	 * Sets a comma-separated list of role formats to be applied to user security groups
	 * from Active Directory.
	 *
	 * @param roleFormats the role formats
	 */
	public void setRoleFormats(String roleFormats) {
		this.roleFormats = roleFormats.split(",");
		List<String> attributes = new ArrayList<>(Arrays.asList(DEFAULT_ROLE_ATTRIBUTES));
		for (String roleFormat : this.roleFormats) {
			if (ROLE_FORMAT_ATTRIBUTES.get(roleFormat) != null)
				attributes.addAll(Arrays.asList(ROLE_FORMAT_ATTRIBUTES.get(roleFormat)));
		}

		this.roleAttributes = attributes.toArray(new String[0]);
	}

	/**
	 * Sets whether the role format is prepended to the role.
	 *
	 * @param prependRoleFormat
	 *            the prepend role format indication
	 */
	public void setPrependRoleFormat(boolean prependRoleFormat) {
		this.prependRoleFormat = prependRoleFormat;
	}

	/**
	 * Sets the maximum amount of directory server connections the pool will hold.
	 *
	 * @param connectionPoolSize
	 *            the connection pool size
	 */
	public void setConnectionPoolSize(int connectionPoolSize) {
		this.connectionPoolSize = connectionPoolSize;
	}

	/**
	 * Sets the maximum amount of time in milliseconds a directory server connection should remain
	 * idle before it is closed.
	 *
	 * @param maxIdleTime
	 *            the maximum idle time
	 */
	public void setMaxIdleTime(long maxIdleTime) {
		this.maxIdleTime = maxIdleTime;
	}

	@Override
	protected String getName() {
		return name;
	}

	@Override
	protected Principal getPrincipal(X509Certificate userCert) {
		try {
			Collection<List<?>> san = userCert.getSubjectAlternativeNames();
			if (san == null || san.isEmpty())
				return null;

			String dn = userCert.getSubjectX500Principal().getName(X500Principal.RFC2253, X500_PRINCIPAL_OID_MAP);
			for (List<?> sanField : san) {
				Integer nameType = (Integer) sanField.get(0);
				// SAN's OtherName, see X509Certificate#getSubjectAlternativeNames() Javadoc
				if (nameType == 0) {
					byte[] otherName = (byte[]) sanField.get(1);
					if (logger.isDebugEnabled())
						logger.debug(sm.getString("activeDirectoryRealm.processingSanOtherName",
								Base64.encodeBase64String(otherName), dn));
					try {
						OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
						if (Arrays.equals(result.getTypeId(), MS_UPN_OID_BYTES)) {
							String upn = OtherNameAsn1Parser.parseUtf8String(result.getValue());
							if (logger.isDebugEnabled())
								logger.debug(sm.getString("activeDirectoryRealm.msUpnExtracted", upn, dn));

							GSSName gssName = new StubGSSName(upn, MS_UPN);

							return getPrincipal(gssName, null, true);
						}
					} catch (CertificateParsingException e) {
						logger.warn(sm.getString("activeDirectoryRealm.sanOtherNameParsingFailed"), e);
					}
				}
			}
		} catch (CertificateParsingException e) {
			logger.warn(sm.getString("activeDirectoryRealm.sanParsingFailed"), e);
		}

		return null;
	}

	@Override
	protected Principal getPrincipal(GSSName gssName, GSSCredential gssCredential) {
		if (gssName.isAnonymous())
			return new ActiveDirectoryPrincipal(gssName, Sid.ANONYMOUS_SID, gssCredential);

		return getPrincipal(gssName, gssCredential, true);
	}

	protected Principal getPrincipal(GSSName gssName, GSSCredential gssCredential, boolean retry) {
		DirContextConnection connection = null;
		try {
			connection = acquire();

			try {
				User user = getUser(connection.context, gssName);

				if (user != null) {
					List<String> roles = getRoles(connection.context, user);

					return new ActiveDirectoryPrincipal(user.getGssName(), user.getSid(), roles, gssCredential,
							user.getAdditionalAttributes());
				}
			} catch (NamingException e) {
				// This construct is an ugly hack for
				// https://bugs.openjdk.java.net/browse/JDK-8273402
				boolean canRetry = false;
				if (e instanceof CommunicationException || e instanceof ServiceUnavailableException)
					canRetry = true;
				else {
					String explanation = e.getExplanation();
					if (explanation.equals("LDAP connection has been closed")
							|| explanation.startsWith("LDAP response read timed out, timeout used:"))
						canRetry = true;
				}

				if (retry && canRetry) {
					logger.error(sm.getString("activeDirectoryRealm.principalSearchFailed.retry", gssName), e);

					close(connection);

					return getPrincipal(gssName, gssCredential, false);
				}

				logger.error(sm.getString("activeDirectoryRealm.principalSearchFailed", gssName), e);

				close(connection);
			}
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.acquire.namingException"), e);
		} finally {
			release(connection);
		}

		return null;
	}

	protected DirContextConnection acquire() throws NamingException {
		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.acquire"));

		DirContextConnection connection = null;

		while (connection == null) {
			connection = connectionPool.pop();

			if (connection != null) {
				long idleTime = System.currentTimeMillis() - connection.lastBorrowTime;
				// TODO support maxIdleTime = -1 (no expiry)
				if (idleTime > maxIdleTime) {
					if (logger.isDebugEnabled())
						logger.debug(sm.getString("activeDirectoryRealm.exceedMaxIdleTime", connection.id));
					close(connection);
					connection = null;
				} else {
					boolean valid = validate(connection);
					if (valid) {
						if (logger.isDebugEnabled())
							logger.debug(sm.getString("activeDirectoryRealm.reuse", connection.id));
					} else {
						close(connection);
						connection = null;
					}
				}
			} else {
				connection = new DirContextConnection();
				open(connection);
			}
		}

		connection.lastBorrowTime = System.currentTimeMillis();

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.acquired", connection.id));

		return connection;
	}

	protected boolean validate(DirContextConnection connection) {
		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.validate", connection.id));

		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.OBJECT_SCOPE);
		controls.setCountLimit(1);
		controls.setReturningAttributes(new String[] { "objectClass" });
		// This applies to a server-side time limit which is actually translated to a second resolution and
		// does not apply to a socket read timeout
		controls.setTimeLimit(500);

		NamingEnumeration<SearchResult> results = null;
		try {
			results = connection.context.search("", "objectclass=*", controls);

			if (results.hasMore())
				return true;
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.validate.namingException", connection.id), e);
		} finally {
			close(results);
		}

		return false;
	}

	protected void release(DirContextConnection connection) {
		if (connection == null)
			return;

		if (connection.context == null)
			return;

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.release", connection.id));
		if (!connectionPool.push(connection))
			close(connection);
	}

	protected void open(DirContextConnection connection) throws NamingException {
		javax.naming.Context context = null;

		if (localDirContextSource) {
			context = ContextBindings.getClassLoader();
			context = (javax.naming.Context) context.lookup("comp/env");
		} else {
			Server server = getServer();
			context = server.getGlobalNamingContext();
		}

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.open"));
		DirContextSource contextSource = (DirContextSource) context
				.lookup(dirContextSourceName);
		connection.context = contextSource.getDirContext();
		connection.id = getNextConnectionId();
		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.opened", connection.id));
	}

	protected void close(DirContextConnection connection) {
		if (connection.context == null)
			return;

		try {
			if (logger.isDebugEnabled())
				logger.debug(sm.getString("activeDirectoryRealm.close", connection.id));
			connection.context.close();
			if (logger.isDebugEnabled())
				logger.debug(sm.getString("activeDirectoryRealm.closed", connection.id));
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.close.namingException", connection.id), e);
		}

		connection.context = null;
	}

	protected void close(NamingEnumeration<?> results) {
		if (results == null)
			return;

		try {
			results.close();
		} catch (NamingException e) {
			; // Ignore
		}
	}

	@Override
	protected void initInternal() throws LifecycleException {
		super.initInternal();

		if (attributes == null)
			attributes = DEFAULT_USER_ATTRIBUTES;

		if (roleFormats == null)
			setRoleFormats(DEFAULT_ROLE_FORMAT);
	}

	@Override
	protected void startInternal() throws LifecycleException {
		connectionPool = new SynchronizedStack<>(connectionPoolSize, connectionPoolSize);

		DirContextConnection connection = null;
		try {
			connection = acquire();

			try {
				String referral = (String) connection.context.getEnvironment().get(DirContext.REFERRAL);

				if ("follow".equals(referral))
					logger.warn(sm.getString("activeDirectoryRealm.referralFollow"));
			} catch (NamingException e) {
				logger.error(sm.getString("activeDirectoryRealm.environmentFailed"), e);

				close(connection);
			}
		} catch (NamingException e) {
			logger.error(sm.getString("activeDirectoryRealm.acquire.namingException"), e);
		} finally {
			release(connection);
		}

		super.startInternal();
	}

	@Override
	protected void stopInternal() throws LifecycleException {
		super.stopInternal();

		DirContextConnection connection = null;
		while ((connection = connectionPool.pop()) != null)
			close(connection);

		connectionPool = null;
	}

	private Oid getStringNameType(GSSName gssName) {
		try {
			return gssName.getStringNameType();
		} catch (GSSException e) {
			return null;
		}
	}

	private String toRealm(Name distinguishedName) {
		LdapName dn = (LdapName) distinguishedName;

		StringBuilder realm = new StringBuilder();
		for(Rdn rdn : dn.getRdns())
			if (rdn.getType().equalsIgnoreCase("DC"))
				realm.insert(0, ((String) rdn.getValue()).toUpperCase(Locale.ROOT) + ".");

		if (realm.length() > 0)
			realm.deleteCharAt(realm.length() - 1);

		return realm.toString();
	}

	protected User getUser(DirContext context, GSSName gssName) throws NamingException {
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

			if (!mapper.supportsGssName(gssName)) {
				if (logger.isDebugEnabled())
					logger.debug(sm.getString("activeDirectoryRealm.nameTypeNotSupported", mapperClassName,
							getStringNameType(gssName), gssName));

				continue;
			}

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
						logger.debug(sm.getString("activeDirectoryRealm.userNotFoundWithMapper", gssName,
								mapperClassName));

					close(results);
				} else
					break;
			} catch (PartialResultException e) {
				logger.debug(sm.getString("activeDirectoryRealm.user.partialResultException",
						mapperClassName, e.getRemainingName()));

				close(results);
			}
		}

		if (results == null || !results.hasMore()) {
			logger.debug(sm.getString("activeDirectoryRealm.userNotFound", gssName));

			close(results);
			return null;
		}

		SearchResult result = results.next();

		try {
			if (results.hasMore()) {
				logger.error(sm.getString("activeDirectoryRealm.duplicateUser", gssName));

				close(results);
				return null;
			}
		} catch (ReferralException e) {
			logger.warn(sm.getString("activeDirectoryRealm.duplicateUser.referralException", gssName,
					e.getRemainingName(), e.getReferralInfo()));
		} catch (PartialResultException e) {
			logger.debug(sm.getString("activeDirectoryRealm.duplicateUser.partialResultException", gssName,
					e.getRemainingName()));
		}

		close(results);

		Attributes userAttributes = result.getAttributes();

		int userAccountControl = Integer
				.parseInt((String) userAttributes.get("userAccountControl").get());

		// Do not allow disabled accounts (UF_ACCOUNT_DISABLE)
		if ((userAccountControl & 0x02) != 0) {
			logger.warn(sm.getString("activeDirectoryRealm.userFoundButDisabled", gssName));
			return null;
		}

		Name dn = getDistinguishedName(context, searchBase, result);
		byte[] sidBytes = (byte[]) userAttributes.get("objectSid;binary").get();
		Sid sid = new Sid(sidBytes);

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.userFound", gssName, dn, sid));

		if (!KRB5_NT_PRINCIPAL.equals(getStringNameType(gssName))) {
			String samAccountName = (String) userAttributes.get("sAMAccountName").get();
			String realm = toRealm(dn);
			String krb5Principal = samAccountName + "@" + realm;

			if (logger.isTraceEnabled())
				logger.trace(sm.getString("activeDirectoryRealm.canonicalizingUser", getStringNameType(gssName),
						KRB5_NT_PRINCIPAL));

			GSSName canonGssName = null;
			try {
				canonGssName = GSSManager.getInstance().createName(krb5Principal, KRB5_NT_PRINCIPAL);
			} catch (GSSException e) {
				logger.warn(sm.getString("activeDirectoryRealm.canonicalizeUserFailed", gssName));

				return null;
			}

			if (logger.isDebugEnabled())
				logger.debug(sm.getString("activeDirectoryRealm.userCanonicalized", canonGssName));

			gssName = canonGssName;
		}

		Attribute memberOfAttr = userAttributes.get("memberOf");

		List<String> memberOfs = new LinkedList<String>();

		if (memberOfAttr != null && memberOfAttr.size() > 0) {
			NamingEnumeration<?> memberOfValues = memberOfAttr.getAll();

			while (memberOfValues.hasMore())
				memberOfs.add((String) memberOfValues.next());

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

		return new User(gssName, sid, memberOfs, additionalAttributesMap);
	}

	protected List<String> getRoles(DirContext context, User user) throws NamingException {
		List<String> roles = new LinkedList<String>();

		if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.retrievingRoles", user.getRoles().size(), user.getGssName()));

		for (String role : user.getRoles()) {
			Name roleRdn = getRelativeName(context, role);

			Attributes roleAttributes = null;
			try {
				roleAttributes = context.getAttributes(roleRdn, this.roleAttributes);
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

			for (String roleFormat: roleFormats) {

				String roleFormatPrefix = prependRoleFormat ? roleFormat + ":" : "";

				switch(roleFormat) {
				case "sid":
					byte[] objectSidBytes = (byte[]) roleAttributes.get("objectSid;binary").get();
					String sidString = new Sid(objectSidBytes).toString();

					roles.add(roleFormatPrefix + sidString);

					Attribute sidHistory = roleAttributes.get("sIDHistory;binary");
					List<String> sidHistoryStrings = new LinkedList<String>();
					if (sidHistory != null) {
						NamingEnumeration<?> sidHistoryEnum = sidHistory.getAll();
						while (sidHistoryEnum.hasMore()) {
							byte[] sidHistoryBytes = (byte[]) sidHistoryEnum.next();
							String sidHistoryString = new Sid(sidHistoryBytes).toString();
							sidHistoryStrings.add(sidHistoryString);

							roles.add(roleFormatPrefix + sidHistoryString);
						}

						close(sidHistoryEnum);
					}

					if (logger.isTraceEnabled()) {
						if (sidHistoryStrings.isEmpty())
							logger.trace(sm.getString("activeDirectoryRealm.foundRoleSidConverted", role,
									sidString));
						else
							logger.trace(
									sm.getString("activeDirectoryRealm.foundRoleSidConverted.withSidHistory",
											role, sidString, sidHistoryStrings));
					}
					break;
				case "name":
					String msDsPrincipalName = (String) roleAttributes.get("msDS-PrincipalName").get();

					roles.add(roleFormatPrefix + msDsPrincipalName);

					if (logger.isTraceEnabled())
						logger.trace(sm.getString("activeDirectoryRealm.foundRoleNameConverted", role,
								msDsPrincipalName));
					break;
				case "nameEx":
						String distinguishedName = (String) roleAttributes.get("distinguishedName").get();
						String samAccountName = (String) roleAttributes.get("sAMAccountName").get();

						NameParser parser = context.getNameParser(StringUtils.EMPTY);
						LdapName dn = (LdapName) parser.parse(distinguishedName);
						String realm = toRealm(dn);
						String nameEx = realm + "\\" + samAccountName;

						roles.add(roleFormatPrefix + nameEx);

						if (logger.isTraceEnabled())
							logger.trace(sm.getString("activeDirectoryRealm.foundRoleNameExConverted", role,
									nameEx));
					break;
				default:
					throw new IllegalArgumentException("The role format '" + roleFormat + "' is invalid");
				}
			}
		}

		if (logger.isTraceEnabled())
			logger.trace(sm.getString("activeDirectoryRealm.foundRoles", roles.size(), user.getGssName(), roles));
		else if (logger.isDebugEnabled())
			logger.debug(sm.getString("activeDirectoryRealm.foundRolesCount", roles.size(),
					user.getGssName()));

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
