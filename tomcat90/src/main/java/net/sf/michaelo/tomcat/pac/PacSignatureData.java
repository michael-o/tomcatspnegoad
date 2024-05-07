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

import java.util.Objects;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6e95edd3-af93-41d4-8303-6c7955297315">{@code PAC_SIGNATURE_DATA}</a>
 * structure from MS-PAC.
 */
public class PacSignatureData {

	public enum SignatureType {

		HMAC_MD5(-138, 16, 23), HMAC_SHA1_96_AES128(15, 12, 17), HMAC_SHA1_96_AES256(16, 12, 18);

		private final int value;
		private final int size;
		private final int eType;

		SignatureType(int value, int size, int eType) {
			this.value = value;
			this.size = size;
			this.eType = eType;
		}

		public int getValue() {
			return value;
		}

		public int getSize() {
			return size;
		}

		public int getEType() {
			return eType;
		}
	}

	private final SignatureType type;
	private final byte[] signature;

	/**
	 * Parses a PAC signature data object from a byte array.
	 *
	 * @param sigDataBytes
	 *            PAC signature data structure encoded as bytes
	 * @throws NullPointerException
	 *             if {@code sigDataBytes} is null
	 * @throws IllegalArgumentException
	 *             if {@code sigDataBytes} is empty
	 * @throws IllegalArgumentException
	 *             if encoded signature type is not supported by {@link SignatureType}
	 */
	public PacSignatureData(byte[] sigDataBytes) {
		Objects.requireNonNull(sigDataBytes, "sigDataBytes cannot be null");
		if (sigDataBytes.length == 0)
			throw new IllegalArgumentException("sigDataBytes cannot be empty");

		PacDataBuffer buf = new PacDataBuffer(sigDataBytes);

		// SignatureType
		int type = buf.getInt();
		if (type == SignatureType.HMAC_MD5.getValue()) {
			this.type = SignatureType.HMAC_MD5;
		} else if (type == SignatureType.HMAC_SHA1_96_AES128.getValue()) {
			this.type = SignatureType.HMAC_SHA1_96_AES128;
		} else if (type == SignatureType.HMAC_SHA1_96_AES256.getValue()) {
			this.type = SignatureType.HMAC_SHA1_96_AES256;
		} else {
			throw new IllegalArgumentException("Unsupported signature type " + type);
		}

		// Signature
		this.signature = new byte[this.type.getSize()];
		buf.get(this.signature);

		// RODCIdentifier ignored completely
	}

	public SignatureType getType() {
		return type;
	}

	public byte[] getSignature() {
		return signature;
	}

}
