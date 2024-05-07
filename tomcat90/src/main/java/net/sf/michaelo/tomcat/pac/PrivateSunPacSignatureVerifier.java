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

import java.security.Key;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import net.sf.michaelo.tomcat.pac.PacSignatureData.SignatureType;
import sun.security.krb5.Checksum;
import sun.security.krb5.EncryptionKey;

/**
 * A PAC signature verifier based on private Sun classes from Java's Kerberos implementation.
 * <p>
 * <strong>Note:</strong> This implementation is far from ideal because it uses private classes
 * which can break anytime. If you are running on Java 17 or newer you <em>must</em> pass
 * {@code --add-exports=java.security.jgss/sun.security.krb5=ALL-UNNAMED} to your JVM. A better
 * solution would be to use the <a href="https://directory.apache.org/kerby/">Apache Kerby</a>
 * library.
 */
public class PrivateSunPacSignatureVerifier extends PacSignatureVerifierBase {

	@Override
	protected void verifyInternal(PacSignatureData signatureData, byte[] data, Key[] keys)
			throws SignatureException {
		SignatureType type = signatureData.getType();
		byte[] expectedSignature = signatureData.getSignature();
		List<byte[]> actualFailedSignatures = new ArrayList<>();
		for (int i = 0; i < keys.length; i++) {
			Key key = keys[i];
			EncryptionKey encKey = new EncryptionKey(type.getEType(), key.getEncoded());
			Checksum checksum = null;
			try {
				checksum = new Checksum(type.getValue(), data, encKey, KU_KERB_NON_KERB_CKSUM_SALT);
			} catch (Exception e) {
				throw new SignatureException("Failed to calculate signature", e);
			}

			byte[] actualSignature = checksum.getBytes();
			if (Arrays.equals(expectedSignature, actualSignature))
				return;
			else
				actualFailedSignatures.add(actualSignature);
		}

		String actualFailedSignaturesStr = actualFailedSignatures.stream()
				.map(Base64.getEncoder()::encodeToString)
				.collect(Collectors.joining(",", "[", "]"));
		throw new SignatureException("Calculated signatures " + actualFailedSignaturesStr
				+ " do not match expected signature '"
				+ Base64.getEncoder().encodeToString(expectedSignature) + "'");
	}

}
