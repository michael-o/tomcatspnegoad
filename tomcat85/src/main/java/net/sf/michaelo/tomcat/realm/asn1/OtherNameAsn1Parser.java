/*
 * Copyright 2021 Michael Osipov
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
package net.sf.michaelo.tomcat.realm.asn1;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.util.Objects;

/**
 * A minimalist ASN.1 parser for X.509 {@code SAN:otherName} according to RFC
 * 5280, section 4.2.1.6.
 * <p>
 * It properly takes
 * <a href="https://bugs.openjdk.java.net/browse/JDK-6776681">JDK-6776681</a>
 * into account and solves
 * <a href="https://bugs.openjdk.java.net/browse/JDK-8277976">JDK-8277976</a>.
 */
public class OtherNameAsn1Parser {

	private static byte CONTEXT_SPECIFIC_BIT = 7;
	private static byte CONSTRUCTED_BIT = 5;

	private static byte MAX_SINGLE_BYTE_LENGTH = 0x7F;
	private static byte SEQUENCE_TAG = 0x30;
	private static byte OID_TAG = 0x06;
	private static byte UTF8STRING_TAG = 0x0C;

	private OtherNameAsn1Parser() {
	};

	/**
	 * Parses the DER-encoded ASN.1 {@code SAN:otherName} field into its components:
	 * {@code type-id} and {@code value}.
	 *
	 * @param otherName a DER-encoded byte array
	 * @return the parse result
	 * @throws NullPointerException        if {@code null} is passed as
	 *                                     {@code otherName}
	 * @throws CertificateParsingException if the DER-encoded byte array does not
	 *                                     comply with ASN.1 DER encoding rules
	 */
	public static OtherNameParseResult parse(byte[] otherName) throws CertificateParsingException {
		Objects.requireNonNull(otherName, "otherName cannot be null");

		ByteBuffer buf = ByteBuffer.wrap(otherName);

		if (!buf.hasRemaining())
			throw new CertificateParsingException("otherName type tag not available, buffer is empty");

		byte tag = buf.get();
		if (tag != SEQUENCE_TAG)
			throw new CertificateParsingException(
					String.format("otherName must start with a SEQUENCE tag, but starts with 0x%02x", tag));

		int seqLen = parseLength(buf);
		if (seqLen > buf.remaining())
			throw new CertificateParsingException(String
					.format("SEQUENCE length (%s B) is larger than the buffer offers (%s B)", seqLen, buf.remaining()));

		int limit = buf.position() + seqLen;
		buf.limit(limit);

		if (!buf.hasRemaining())
			throw new CertificateParsingException("otherName fields not available, buffer is empty");

		byte[] typeId = parseOid(buf);
		byte[] value = parseValue(buf);

		return new OtherNameParseResult(typeId, value);
	}

	/**
	 * Parses a DER-encoded ASN.1 {@code UTF8String} to a Java string:
	 *
	 * @param string a DER-encoded byte array
	 * @return the converted Java string
	 * @throws NullPointerException        if {@code null} is passed as
	 *                                     {@code string}
	 * @throws CertificateParsingException if the DER-encoded byte array does not
	 *                                     comply with ASN.1 defininiton
	 */
	public static String parseUtf8String(byte[] string) throws CertificateParsingException {
		Objects.requireNonNull(string, "string cannot be null");

		ByteBuffer buf = ByteBuffer.wrap(string);

		if (!buf.hasRemaining())
			throw new CertificateParsingException("string type tag not available, buffer is empty");

		byte tag = buf.get();
		if (tag != UTF8STRING_TAG)
			throw new CertificateParsingException(
					String.format("string must start with a UTF8String tag, but starts with 0x%02x", tag));

		int strLen = parseLength(buf);
		if (strLen > buf.remaining())
			throw new CertificateParsingException(String.format(
					"UTF8String length (%s B) is larger than the buffer offers (%s B)", strLen, buf.remaining()));

		byte[] str = new byte[strLen];
		buf.get(str);

		return new String(str, StandardCharsets.UTF_8);
	}

	private static int parseLength(ByteBuffer buf) throws CertificateParsingException {
		if (!buf.hasRemaining())
			throw new CertificateParsingException("Type length not available, buffer is empty");

		int typeLen = buf.get() & 0xFF;
		if (typeLen <= MAX_SINGLE_BYTE_LENGTH)
			return typeLen;

		int n = typeLen & MAX_SINGLE_BYTE_LENGTH;

		if (n == 0)
			throw new CertificateParsingException("Indefinite type length is not supported");

		if (n > 2)
			throw new CertificateParsingException("Type length above 64 KiB ist not supported");

		if (n > buf.remaining())
			throw new CertificateParsingException(String
					.format("Type length bytes (%s B) are larger than the buffer offers (%s B)", n, buf.remaining()));

		typeLen = 0;
		for (int i = 0; i < n; i++)
			typeLen = (typeLen << 8) | (buf.get() & 0xFF);

		return typeLen;
	}

	private static byte[] parseOid(ByteBuffer buf) throws CertificateParsingException {
		if (!buf.hasRemaining())
			throw new CertificateParsingException("OID type tag not available, buffer is empty");

		byte tag = buf.get();
		if (tag != OID_TAG)
			throw new CertificateParsingException(
					String.format("OID must start with an OBJECT IDENTIFIER tag, but is 0x%02x", tag));

		int oidLen = parseLength(buf);
		if (oidLen > buf.remaining())
			throw new CertificateParsingException(
					String.format("OBJECT IDENTIFIER length (%s B) is larger than the buffer offers (%s B)", oidLen,
							buf.remaining()));

		if (!buf.hasRemaining())
			throw new CertificateParsingException("OID value not available, buffer is empty");

		byte[] oid = new byte[oidLen];
		buf.get(oid);

		return oid;
	}

	private static byte[] parseValue(ByteBuffer buf) throws CertificateParsingException {
		if (!buf.hasRemaining())
			throw new CertificateParsingException("Value type tag not available, buffer is empty");

		byte tag = buf.get();
		if (!(((tag >> CONTEXT_SPECIFIC_BIT) & 1) != 0 && ((tag >> CONSTRUCTED_BIT) & 1) != 0))
			throw new CertificateParsingException("Value must be explicitly encoded");

		int tagNumber = tag & 0xFF;
		tagNumber &= ~(1 << CONTEXT_SPECIFIC_BIT);
		tagNumber &= ~(1 << CONSTRUCTED_BIT);

		if (tagNumber != 0)
			throw new CertificateParsingException("Value tag number must be 0, but is " + tagNumber);

		int valLen = parseLength(buf);
		if (valLen > buf.remaining())
			throw new CertificateParsingException(String
					.format("Value length (%s B) is larger than the buffer offers (%s B)", valLen, buf.remaining()));

		int limit = buf.position() + valLen;
		buf.limit(limit);

		if (!buf.hasRemaining())
			throw new CertificateParsingException("Value not available, buffer is empty");

		// Workaround for https://bugs.openjdk.java.net/browse/JDK-6776681
		int pos = buf.position();
		tag = buf.get();
		tagNumber = tag & 0xFF;
		tagNumber &= ~(1 << CONTEXT_SPECIFIC_BIT);
		tagNumber &= ~(1 << CONSTRUCTED_BIT);
		if (((tag >> CONTEXT_SPECIFIC_BIT) & 1) != 0 && ((tag >> CONSTRUCTED_BIT) & 1) != 0 && tagNumber == 0) {
			valLen = parseLength(buf);
			if (valLen > buf.remaining())
				throw new CertificateParsingException(String.format(
						"Value length (%s B) is larger than the buffer offers (%s B)", valLen, buf.remaining()));

			limit = buf.position() + valLen;
			buf.limit(limit);
		} else
			buf.position(pos);

		if (!buf.hasRemaining())
			throw new CertificateParsingException("Value not available, buffer is empty");

		byte[] value = new byte[valLen];
		buf.get(value);

		return value;
	}

}
