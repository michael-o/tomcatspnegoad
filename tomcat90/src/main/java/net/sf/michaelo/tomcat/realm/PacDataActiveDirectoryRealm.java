/*
 * Copyright 2024 Michael Osipov
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

import java.security.Key;
import java.security.Principal;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.catalina.authenticator.SSLAuthenticator;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

import com.sun.security.jgss.AuthorizationDataEntry;
import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;

import net.sf.michaelo.tomcat.authenticator.SpnegoAuthenticator;
import net.sf.michaelo.tomcat.pac.GroupMembership;
import net.sf.michaelo.tomcat.pac.KerbValidationInfo;
import net.sf.michaelo.tomcat.pac.Pac;
import net.sf.michaelo.tomcat.pac.PrivateSunPacSignatureVerifier;
import net.sf.michaelo.tomcat.pac.asn1.AdIfRelevantAsn1Parser;

/**
 * A realm which decodes authorization data from <em>already authenticated</em> users from Active
 * Directory via <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962">MS-PAC</a>.
 * <p>
 * This realm requires your JVM to provide an {@link ExtendedGSSContext} implementation. It will use
 * {@link InquireType#KRB5_GET_AUTHZ_DATA} to extract {@code AuthorizationData} according to RFC 4120,
 * section 5.2.6 from an established security context, and use the {@link Pac} parser to extract all
 * relevant authorization data (group SIDs), validate the PAC data server signature with the
 * {@link PrivateSunPacSignatureVerifier} and the supplied keytab (login context) and process the
 * data according to <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/4ad7ed1f-0bfa-4b5f-bda3-fedbc549a6c0">MS-KILE,
 * section 3.4.5.3</a>.
 *
 * <h2 id="configuration">Configuration</h2> Following options can be configured:
 * <ul>
 * <li>{@code loginEntryName}: the login entry identical to the one from
 * {@link SpnegoAuthenticator#getLoginEntryName()}.</li>
 * <li>{@code prependRoleFormat}: whether the role format is prepended to the role as
 * <code>{roleFormat}:{role}</code>. Default is {@code false}.</li>
 * <li>{@code addAdditionalAttributes}: whether the following additional attributes with their LDAP
 * name counterparts are added to the principal: {@code sAMAccountName}, {@code displayName},
 * {@code userPrincipalName} (if available), {@code msDS-PrincipalName}. Default is
 * {@code false}.</li>
 * </ul>
 * <p>
 * <strong>Note:</strong> This realm is meant to be an alternative to the
 * {@link ActiveDirectoryRealm} when no more additional attributes or other role formats are
 * required beyond those provided by the PAC data and {@link SpnegoAuthenticator SPNEGO
 * authentication} is used ({@link SSLAuthenticator X.509 authentication} is not supported).
 * Moreover, all processing happens in memory, for that reason it is <em>orders of magnitude
 * faster</em> than the previously mentioned one.
 */
public class PacDataActiveDirectoryRealm extends ActiveDirectoryRealmBase {

	private static final long USER_ACCOUNT_DISABLED = 0x00000001L;
	private static final long USER_NORMAL_ACCOUNT = 0x00000010L;
	private static final long USER_WORKSTATION_TRUST_ACCOUNT = 0x00000080L;

	protected String loginEntryName;
	protected boolean prependRoleFormat;
	protected boolean addAdditionalAttributes;

	/**
	 * Sets the login entry name which establishes the security context.
	 *
	 * @param loginEntryName
	 *            the login entry name
	 */
	public void setLoginEntryName(String loginEntryName) {
		this.loginEntryName = loginEntryName;
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
	 * Sets whether the additional attributes are added to the principal.
	 *
	 * @param addAdditionalAttributes
	 *            the add additional attributes indication
	 */
	public void setAddAdditionalAttributes(boolean addAdditionalAttributes) {
		this.addAdditionalAttributes = addAdditionalAttributes;
	}

	protected Principal getPrincipal(GSSName gssName, GSSCredential gssCredential,
			GSSContext gssContext) {
		if (gssName.isAnonymous())
			return new ActiveDirectoryPrincipal(gssName, Sid.ANONYMOUS_SID, gssCredential);

		if (gssContext instanceof ExtendedGSSContext) {
			ExtendedGSSContext extGssContext = (ExtendedGSSContext) gssContext;

			AuthorizationDataEntry[] adEntries = null;
			try {
				adEntries = (AuthorizationDataEntry[]) extGssContext
						.inquireSecContext(InquireType.KRB5_GET_AUTHZ_DATA);
			} catch (GSSException e) {
				logger.warn(sm.getString("krb5AuthzDataRealmBase.inquireSecurityContextFailed"), e);
			}

			if (adEntries == null) {
				if (logger.isDebugEnabled())
					logger.debug(sm.getString("krb5AuthzDataRealmBase.noDataProvided", gssName));
				return null;
			}

			Optional<AuthorizationDataEntry> pacDataEntry = Arrays.stream(adEntries)
					.filter(adEntry -> adEntry.getType() == AdIfRelevantAsn1Parser.AD_IF_RELEVANT)
					.map(adEntry -> AdIfRelevantAsn1Parser.parse(adEntry.getData()))
					.flatMap(List::stream)
					.filter(adEntry -> adEntry.getType() == AdIfRelevantAsn1Parser.AD_WIN2K_PAC)
					.findFirst();

			if (pacDataEntry.isPresent()) {
				Pac pac = new Pac(pacDataEntry.get().getData(),
						new PrivateSunPacSignatureVerifier());

				Key[] keys = getKeys();
				try {
					pac.verifySignature(keys);
				} catch (SignatureException e) {
					logger.warn(
							sm.getString("pacDataActiveDirectoryRealm.signatureVerificationFailed"),
							e);
					return null;
				}

				KerbValidationInfo kerbValidationInfo = pac.getKerbValidationInfo();
				long userAccountControl = kerbValidationInfo.getUserAccountControl();

				if ((userAccountControl & USER_ACCOUNT_DISABLED) != 0L) {
					logger.warn(sm.getString("activeDirectoryRealm.userFoundButDisabled", gssName));
					return null;
				}

				if ((userAccountControl & USER_NORMAL_ACCOUNT) == 0L
						&& (userAccountControl & USER_WORKSTATION_TRUST_ACCOUNT) == 0L) {
					logger.warn(
							sm.getString("activeDirectoryRealm.userFoundButNotSupported", gssName));
					return null;
				}

				long userId = kerbValidationInfo.getUserId();
				Sid sid = null;
				if (userId == 0L) {
					sid = kerbValidationInfo.getExtraSids().get(0).getSid();
				} else {
					sid = kerbValidationInfo.getLogonDomainId().append(userId);
				}
				Collection<Sid> groups = new HashSet<>();

				Sid primaryGroupSid = kerbValidationInfo.getLogonDomainId()
						.append(kerbValidationInfo.getPrimaryGroupId());
				groups.add(primaryGroupSid);
				for (GroupMembership membership : kerbValidationInfo.getGroupIds()) {
					groups.add(kerbValidationInfo.getLogonDomainId()
							.append(membership.getRelativeId()));
				}
				if (kerbValidationInfo.getExtraSids() != null) {
					long n = userId == 0L ? 1L : 0L;
					groups.addAll(kerbValidationInfo.getExtraSids().stream().skip(n)
							.map(extraSid -> extraSid.getSid()).collect(Collectors.toList()));
				}
				if (kerbValidationInfo.getResourceGroupDomainSid() != null) {
					groups.addAll(kerbValidationInfo.getResourceGroupIds().stream()
							.map(resourceGroupId -> kerbValidationInfo.getResourceGroupDomainSid()
									.append(resourceGroupId.getRelativeId()))
							.collect(Collectors.toList()));
				}

				Map<String, Object> additionalAttributesMap = null;
				if (addAdditionalAttributes) {
					additionalAttributesMap = new HashMap<String, Object>();
					additionalAttributesMap.put("sAMAccountName",
							kerbValidationInfo.getEffectiveName());
					additionalAttributesMap.put("displayName", kerbValidationInfo.getFullName());
					additionalAttributesMap.put("msDS-PrincipalName",
							kerbValidationInfo.getLogonDomainName() + "\\"
									+ kerbValidationInfo.getEffectiveName());
					if (pac.getUpnDnsInfo() != null) {
						additionalAttributesMap.put("userPrincipalName",
								pac.getUpnDnsInfo().getUpn());
					}
				}

				String roleFormatPrefix = prependRoleFormat ? "sid:" : "";
				List<String> roles = groups.stream().map(String::valueOf)
						.map(group -> roleFormatPrefix + group).collect(Collectors.toList());

				if (logger.isTraceEnabled())
					logger.trace(sm.getString("activeDirectoryRealm.foundRoles", roles.size(),
							gssName, roles));
				else if (logger.isDebugEnabled())
					logger.debug(sm.getString("activeDirectoryRealm.foundRolesCount", roles.size(),
							gssName));

				return new ActiveDirectoryPrincipal(gssName, sid, roles, gssCredential,
						additionalAttributesMap);
			} else {
				if (logger.isDebugEnabled())
					logger.debug(
							sm.getString("pacDataActiveDirectoryRealm.noDataProvided", gssName));
			}
		} else {
			logger.error(sm.getString("krb5AuthzDataRealmBase.incompatibleSecurityContextType"));
		}

		return null;
	}

	protected Key[] getKeys() {
		LoginContext lc = null;
		try {
			lc = new LoginContext(loginEntryName);
			lc.login();
			Subject subject = lc.getSubject();
			Set<KerberosPrincipal> principals = subject.getPrincipals(KerberosPrincipal.class);
			KerberosPrincipal principal = principals.iterator().next();
			Set<KeyTab> privateCredentials = subject.getPrivateCredentials(KeyTab.class);
			KeyTab keyTab = privateCredentials.iterator().next();
			return keyTab.getKeys(principal);
		} catch (LoginException e) {
			throw new IllegalStateException(
					"Failed to load Kerberos keys for login entry '" + loginEntryName + "'", e);
		} finally {
			if (lc != null) {
				try {
					lc.logout();
				} catch (LoginException e) {
					; // Ignore
				}
			}
		}
	}

}
