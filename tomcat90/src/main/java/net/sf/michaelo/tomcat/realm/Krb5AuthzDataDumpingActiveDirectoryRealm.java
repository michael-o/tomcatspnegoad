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

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Principal;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Set;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

import com.sun.security.jgss.AuthorizationDataEntry;
import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;

import net.sf.michaelo.tomcat.pac.Krb5AuthzDataDumpPrinter;

/**
 * A realm which extracts and dumps Kerberos {@code AuthorizationData} and always returns a {@code null}.
 * Use the {@link CombinedRealm} to authenticate against this one first and then against the actual
 * one next.
 * <p>
 * This realm requires your JVM to provide an {@link ExtendedGSSContext} implementation. It will use
 * {@link InquireType#KRB5_GET_AUTHZ_DATA} to extract {@code AuthorizationData} according to RFC 4120,
 * section 5.2.6 from an established security context, dump to
 * <code>{catalina.base}/work/KRB5_AUTHZ_DATA/{gssName}/{yyyyMMdd'T'HHmmss.SSS}{#n?}</code> and
 * continue as described.
 * <p>
 * <strong>Note</strong>: Use this realm for testing/analysis purposes only along with the
 * {@link Krb5AuthzDataDumpPrinter}.
 */
public class Krb5AuthzDataDumpingActiveDirectoryRealm extends ActiveDirectoryRealmBase {

	private static final DateTimeFormatter TS_FORMAT = DateTimeFormatter
			.ofPattern("yyyyMMdd'T'HHmmss.SSS").withZone(ZoneId.systemDefault());

	protected Principal getPrincipal(GSSName gssName, GSSCredential gssCredential,
			GSSContext gssContext) {
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

			File catalinaBase = getServer().getCatalinaBase();
			Path workDir = catalinaBase.toPath().resolve("work");
			Instant id = Instant.now();

			Path dumpDir = workDir.resolve("KRB5_AUTHZ_DATA").resolve(gssName.toString());
			try {
				Path dumpFile = createDumpFile(dumpDir, id);
				try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(dumpFile))) {
					for (AuthorizationDataEntry adEntry : adEntries) {
						w.printf("%d %s%n", adEntry.getType(),
								Base64.getEncoder().encodeToString(adEntry.getData()));
					}
				}
			} catch (IOException e) {
				logger.warn(sm.getString(
						"krb5AuthzDataDumpingActiveDirectoryRealm.dumpingKrb5AuthzDataFailed",
						gssName), e);
			}
		} else {
			logger.error(sm.getString("krb5AuthzDataRealmBase.incompatibleSecurityContextType"));
		}

		return null;
	}

	private Path createDumpFile(Path dumpDir, Instant id) throws IOException {
		Files.createDirectories(dumpDir);
		String formattedTimestamp = TS_FORMAT.format(id);
		Path dumpFile = dumpDir.resolve(formattedTimestamp);
		int i = 2;
		while (Files.exists(dumpFile)) {
			dumpFile = dumpDir.resolve(formattedTimestamp + "#" + i++);
		}
		if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
			Set<PosixFilePermission> ownerWritable = PosixFilePermissions.fromString("rw-------");
			FileAttribute<?> permissions = PosixFilePermissions.asFileAttribute(ownerWritable);
			Files.createFile(dumpFile, permissions);
		}
		return dumpFile;
	}

}
