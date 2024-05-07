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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import net.sf.michaelo.tomcat.pac.PacSignatureData.SignatureType;

/**
 * A base implementation of the {@link PacSignatureVerifier}. Implementors are expected to implement
 * {@link #verifyInternal(PacSignatureData, byte[], Key[])} only.
 */
public abstract class PacSignatureVerifierBase implements PacSignatureVerifier {

	private static final Map<String, Integer> ETYPE_MAPPER = new HashMap<>();

	static {
		ETYPE_MAPPER.put("ArcFourHmac", SignatureType.HMAC_MD5.getEType());
		ETYPE_MAPPER.put("rc4-hmac", SignatureType.HMAC_MD5.getEType());
		ETYPE_MAPPER.put("23", SignatureType.HMAC_MD5.getEType());
		ETYPE_MAPPER.put("AES128", SignatureType.HMAC_SHA1_96_AES128.getEType());
		ETYPE_MAPPER.put("aes128-cts-hmac-sha1-96", SignatureType.HMAC_SHA1_96_AES128.getEType());
		ETYPE_MAPPER.put("17", SignatureType.HMAC_SHA1_96_AES128.getEType());
		ETYPE_MAPPER.put("AES256", SignatureType.HMAC_SHA1_96_AES256.getEType());
		ETYPE_MAPPER.put("aes256-cts-hmac-sha1-96", SignatureType.HMAC_SHA1_96_AES256.getEType());
		ETYPE_MAPPER.put("18", SignatureType.HMAC_SHA1_96_AES256.getEType());
	}

	@Override
	public void verify(PacSignatureData signatureData, byte[] data, Key[] keys)
			throws SignatureException {
		Objects.requireNonNull(signatureData, "signatureData cannot be null");
		Objects.requireNonNull(data, "data cannot be null");
		if (data.length == 0)
			throw new IllegalArgumentException("data cannot be empty");
		Objects.requireNonNull(keys, "data cannot be null");
		if (keys.length == 0)
			throw new IllegalArgumentException("keys cannot be empty");

		Key[] filteredKeys = Arrays.stream(keys)
				.filter(key -> ETYPE_MAPPER.get(key.getAlgorithm()) != null && ETYPE_MAPPER
						.get(key.getAlgorithm()) == signatureData.getType().getEType())
				.toArray(Key[]::new);
		if (filteredKeys.length == 0)
			throw new IllegalArgumentException(
					"No suitable keys provided for etype " + signatureData.getType().getEType());

		verifyInternal(signatureData, data, filteredKeys);
	}

	/**
	 * In contrast to {@link #verify(PacSignatureData, byte[], Key[])} all input parameters are
	 * validated before passed down.
	 *
	 * @see #verify(PacSignatureData, byte[], Key[])
	 */
	abstract protected void verifyInternal(PacSignatureData signatureData, byte[] data, Key[] keys)
			throws SignatureException;

}
