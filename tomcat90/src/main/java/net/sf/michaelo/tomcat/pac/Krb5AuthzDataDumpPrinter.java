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
package net.sf.michaelo.tomcat.pac;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import com.sun.security.jgss.AuthorizationDataEntry;

import net.sf.michaelo.tomcat.authenticator.SpnegoAuthenticator;
import net.sf.michaelo.tomcat.pac.asn1.AdIfRelevantAsn1Parser;
import net.sf.michaelo.tomcat.realm.Krb5AuthzDataDumpingActiveDirectoryRealm;
import net.sf.michaelo.tomcat.realm.Sid;

/**
 * A Kerberos {@code AuthorizationData} dump printer produced by
 * {@link Krb5AuthzDataDumpingActiveDirectoryRealm}.
 * <p>
 * This class can be called via its main method, it supports the following optional parameters:
 * <ul>
 * <li>output format {@code --format} {@code listing} (default) or {@code sql},</li>
 * <li>verify the PAC server signature with the {@link PrivateSunPacSignatureVerifier} and a login
 * context {@code --verify-signature} <code>{loginEntryName}</code>, The configuration of the login
 * entry must be identical to the one from {@link SpnegoAuthenticator#getLoginEntryName()}</li>
 * </ul>
 * and the following positional parameters:
 * <ul>
 * <li>dump file/directory {@code path...}: either a file or a directory containing dumps.</li>
 * </ul>
 * <p>
 * The {@code sql} format output can be used to import the data into a SQLite database for later
 * analysis.
 */
public class Krb5AuthzDataDumpPrinter {

	private static final AtomicInteger PAC_ID_GENERATOR = new AtomicInteger();

	private static void dumpFile(Path file, String format, KerberosKey[] keys)
			throws IOException, SignatureException {
		System.err.printf("Processing file '%s'%n", file);
		List<AuthorizationDataEntry> adEntries = new ArrayList<>();
		try (Scanner scanner = new Scanner(file)) {
			while (scanner.hasNext()) {
				int type = scanner.nextInt();
				byte[] data = Base64.getDecoder().decode(scanner.next());
				adEntries.add(new AuthorizationDataEntry(type, data));
			}
		}

		for (AuthorizationDataEntry adEntry : adEntries) {
			int type = adEntry.getType();
			byte[] data = adEntry.getData();
			switch (type) {
			case AdIfRelevantAsn1Parser.AD_IF_RELEVANT:
				List<AuthorizationDataEntry> adIfRelevantEntries = AdIfRelevantAsn1Parser
						.parse(data);
				for (AuthorizationDataEntry adIfRelevantEntry : adIfRelevantEntries) {
					int adIfRelevantType = adIfRelevantEntry.getType();
					byte[] adIfRelevantTypeData = adIfRelevantEntry.getData();
					switch (adIfRelevantType) {
					case AdIfRelevantAsn1Parser.AD_WIN2K_PAC:
						int pacId = PAC_ID_GENERATOR.incrementAndGet();

						Pac pac = new Pac(adIfRelevantTypeData,
								new PrivateSunPacSignatureVerifier());

						if (keys != null) {
							if (format.equals("listing"))
								System.out.print("Verifying PAC server signature...");
							pac.verifySignature(keys);
							if (format.equals("listing"))
								System.out.println("PASSED");
						}

						KerbValidationInfo kerbValidationInfo = pac.getKerbValidationInfo();
						String effectiveName = kerbValidationInfo.getEffectiveName();
						String fullName = kerbValidationInfo.getFullName();
						String logonScript = kerbValidationInfo.getLogonScript();
						String profilePath = kerbValidationInfo.getProfilePath();
						String homeDirectory = kerbValidationInfo.getHomeDirectory();
						String homeDirectoryDrive = kerbValidationInfo.getHomeDirectoryDrive();
						long userId = kerbValidationInfo.getUserId();
						long primaryGroupId = kerbValidationInfo.getPrimaryGroupId();
						List<GroupMembership> groupIds = kerbValidationInfo.getGroupIds();
						long userFlags = kerbValidationInfo.getUserFlags();
						String logonServer = kerbValidationInfo.getLogonServer();
						String logonDomainName = kerbValidationInfo.getLogonDomainName();
						Sid logonDomainId = kerbValidationInfo.getLogonDomainId();
						long userAccountControl = kerbValidationInfo.getUserAccountControl();
						List<KerbSidAndAttributes> extraSids = kerbValidationInfo.getExtraSids();
						Sid resourceGroupDomainSid = kerbValidationInfo.getResourceGroupDomainSid();
						List<GroupMembership> resourceGroupIds = kerbValidationInfo
								.getResourceGroupIds();
						switch (format) {
						case "listing":
							System.out.println("KerbValidationInfo:");
							System.out.println("  effectiveName: " + effectiveName);
							System.out.println("  fullName: " + fullName);
							System.out.println("  logonScript: " + logonScript);
							System.out.println("  profilePath: " + profilePath);
							System.out.println("  homeDirectory: " + homeDirectory);
							System.out.println("  homeDirectoryDrive: " + homeDirectoryDrive);
							System.out.println("  userId: " + userId);
							System.out.println("  primaryGroupId: " + primaryGroupId);
							System.out.println("  groupIds (" + groupIds.size() + "):");
							for (GroupMembership groupId : groupIds) {
								System.out.println("    - " + groupId + " ("
										+ logonDomainId.append(groupId.getRelativeId()) + ")");
							}
							System.out.printf("  userFlags: 0x%08X%n", userFlags);
							System.out.println("  logonServer: " + logonServer);
							System.out.println("  logonDomainName: " + logonDomainName);
							System.out.println("  logonDomainId: " + logonDomainId);
							System.out.printf("  userAccountControl: 0x%08X%n", userAccountControl);
							if (extraSids != null) {
								System.out.println("  extraSids (" + extraSids.size() + "):");
								for (KerbSidAndAttributes extraSid : extraSids) {
									System.out.println("    - " + extraSid);
								}
							}
							if (resourceGroupDomainSid != null) {
								System.out.println(
										"  resourceGroupDomainSid: " + resourceGroupDomainSid);
								System.out.println(
										"  resourceGroupIds (" + resourceGroupIds.size() + "):");
								for (GroupMembership resourceGroupId : resourceGroupIds) {
									System.out.println("    - " + resourceGroupId + " ("
											+ resourceGroupDomainSid.append(resourceGroupId.getRelativeId()) + ")");
								}
							}
							break;
						case "sql":
							System.out.printf(
									"insert into kerb_validation_info(pacId, effectiveName, fullName, logonScript, profilePath, homeDirectory, homeDirectoryDrive, userId, primaryGroupId, userFlags, logonServer, logonDomainName, logonDomainId, userAccountControl, resourceGroupDomainSid)"
											+ " values(%d, '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, %d, '%s', '%s', '%s', %d, %s);%n",
									pacId, effectiveName, fullName, logonScript, profilePath,
									homeDirectory, homeDirectoryDrive, userId, primaryGroupId,
									userFlags, logonServer, logonDomainName, logonDomainId,
									userAccountControl, nullSafe(resourceGroupDomainSid));
							for (GroupMembership groupId : groupIds) {
								System.out.printf(
										"insert into group_ids(pacId, relativeId, attributes) values(%d, %d, %d);%n",
										pacId, groupId.getRelativeId(), groupId.getAttributes());
							}
							if (extraSids != null) {
								for (KerbSidAndAttributes extraSid : extraSids) {
									System.out.printf(
											"insert into extra_sids(pacId, sid, attributes) values(%d, '%s', %d);%n",
											pacId, extraSid.getSid(), extraSid.getAttributes());
								}
							}
							if (resourceGroupDomainSid != null) {
								for (GroupMembership resourceGroupId : resourceGroupIds) {
									System.out.printf(
											"insert into resource_group_ids(pacId, relativeId, attributes) values(%d, %d, %d);%n",
											pacId, resourceGroupId.getRelativeId(),
											resourceGroupId.getAttributes());
								}
							}
							break;
						}
						UpnDnsInfo upnDnsInfo = pac.getUpnDnsInfo();
						if (upnDnsInfo != null) {
							String upn = upnDnsInfo.getUpn();
							String dnsDomainName = upnDnsInfo.getDnsDomainName();
							long flags = upnDnsInfo.getFlags();
							String samName = upnDnsInfo.getSamName();
							Sid sid = upnDnsInfo.getSid();
							switch (format) {
							case "listing":
								System.out.println("UpnDnsInfo:");
								System.out.println("  upn: " + upn);
								System.out.println("  dnsDomainName: " + dnsDomainName);
								System.out.printf("  flags: 0x%08X%n", flags);
								if (samName != null) {
									System.out.println("  samName: " + samName);
									System.out.println("  sid: " + sid);
								}
								break;
							case "sql":
								System.out.printf(
										"insert into upn_dns_info(pacId, upn, dnsDomainName, flags, samName, sid)"
												+ " values(%d, '%s', '%s', %d, %s, %s);%n",
										pacId, upn, dnsDomainName, flags, nullSafe(samName),
										nullSafe(sid));
								break;
							}
						}
						PacClientInfo pacClientInfo = pac.getPacClientInfo();
						switch (format) {
						case "listing":
							System.out.println("PacClientInfo:");
							System.out.println("  name: " + pacClientInfo.getName());
							break;
						}
						PacSignatureData serverSignature = pac.getServerSignature();
						PacSignatureData kdcSignature = pac.getKdcSignature();
						switch (format) {
						case "listing":
							System.out.println("ServerSignature:");
							System.out.println("  type: " + serverSignature.getType());
							System.out.println("  signature: " + Base64.getEncoder()
									.encodeToString(serverSignature.getSignature()));
							System.out.println("KdcSignature:");
							System.out.println("  type: " + kdcSignature.getType());
							System.out.println("  signature: " + Base64.getEncoder()
									.encodeToString(kdcSignature.getSignature()));
							break;
						}
						break;
					default:
						System.err.println(
								"Ignoring unsupported authorization data (AD-IF-RELEVANT) entry type "
										+ adIfRelevantType + " with data "
										+ Base64.getEncoder().encodeToString(adIfRelevantTypeData));
						break;
					}
				}
				break;
			default:
				System.err.println("Ignoring unsupported authorization data entry type " + type
						+ " with data " + Base64.getEncoder().encodeToString(data));
				break;
			}
		}
	}

	private static String nullSafe(Object obj) {
		return obj != null ? "'" + obj + "'" : "NULL";
	}

	public static void main(String[] args) throws IOException, SignatureException {
		if (args.length == 0) {
			System.err.println("No arguments provided");
			System.exit(1);
		}

		int positionalArgs = 0;
		String formatValue = "listing";
		String verifySignatureValue = null;
		boolean breakLoop = false;
		while (positionalArgs < args.length && !breakLoop) {
			switch (args[positionalArgs]) {
			case "--format":
				positionalArgs++;
				if (positionalArgs > args.length - 1)
					throw new IllegalArgumentException("Missing option value for '--format'");
				formatValue = args[positionalArgs++];
				break;
			case "--verify-signature":
				positionalArgs++;
				if (positionalArgs > args.length - 1)
					throw new IllegalArgumentException(
							"Missing option value for '--verify-signature'");
				verifySignatureValue = args[positionalArgs++];
				break;
			case "--":
				positionalArgs++;
				breakLoop = true;
				break;
			default:
				breakLoop = true;
				break;
			}
		}

		if (!formatValue.equals("listing") && !formatValue.equals("sql"))
			throw new IllegalArgumentException("Unsupported format value: " + formatValue);

		KerberosKey[] keysValue = null;
		if (verifySignatureValue != null) {
			String loginEntryName = verifySignatureValue;
			LoginContext lc = null;
			try {
				lc = new LoginContext(loginEntryName);
				lc.login();
				Subject subject = lc.getSubject();
				KerberosPrincipal principal = subject.getPrincipals(KerberosPrincipal.class)
						.iterator().next();
				KeyTab keyTab = subject.getPrivateCredentials(KeyTab.class).iterator().next();
				keysValue = keyTab.getKeys(principal);
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
		final KerberosKey[] keys = keysValue;

		final String format = formatValue;
		if (format.equals("sql")) {
			System.out.println("BEGIN TRANSACTION;");
			try (BufferedReader r = new BufferedReader(new InputStreamReader(
					Krb5AuthzDataDumpPrinter.class
							.getResourceAsStream("/net/sf/michaelo/tomcat/pac/create-tables.sql"),
					StandardCharsets.UTF_8))) {
				r.lines().forEach(line -> System.out.println(line));
			}
		}

		for (int i = positionalArgs; i < args.length; i++) {
			Path path = Paths.get(args[i]);
			if (Files.notExists(path)) {
				System.err.printf("Ignoring non-existing path '%s'%n", path);
				continue;
			}
			if (Files.isRegularFile(path)) {
				dumpFile(path, format, keys);
			} else if (Files.isDirectory(path)) {
				Files.walk(path).filter(Files::isRegularFile).forEach(file -> {
					try {
						dumpFile(file, format, keys);
					} catch (IOException e) {
						throw new UncheckedIOException(e);
					} catch (SignatureException e) {
						throw new RuntimeException(e);
					}
				});
			} else {
				System.err.printf("Ignoring unsupported path '%s'%n", path);
				continue;
			}
		}

		if (format.equals("sql")) {
			System.out.println("COMMIT;");
		}
	}

}
