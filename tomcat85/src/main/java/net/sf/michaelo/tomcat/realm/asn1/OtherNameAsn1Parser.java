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

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.apache.tomcat.util.buf.Asn1Parser;

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

	private static byte UTF8STRING_TAG = 0x0C;

	private OtherNameAsn1Parser() {
	}

	/**
	 * Parses the DER-encoded ASN.1 {@code SAN:otherName} field into its components:
	 * {@code type-id} and {@code value}.
	 *
	 * @param otherName a DER-encoded byte array
	 * @return the parse result
	 * @throws NullPointerException     if {@code otherName} is {@code null}
	 * @throws IllegalArgumentException if {@code otherName} is empty or if the
	 *                                  DER-encoded byte array does not comply with
	 *                                  ASN.1 DER encoding rules
	 */
	public static OtherNameParseResult parse(byte[] otherName) {
		Objects.requireNonNull(otherName, "otherName cannot be null");
		if (otherName.length == 0)
			throw new IllegalArgumentException("otherName cannot be empty");

		Asn1Parser parser = new Asn1Parser(otherName);

		parser.parseTagSequence();
		parser.parseFullLength();

		byte[] typeId = parser.parseOIDAsBytes();
		byte[] value = parser.parseAttributeAsBytes(0);
		parser = new Asn1Parser(value);
		// Workaround for https://bugs.openjdk.java.net/browse/JDK-6776681
		if (parser.peekTag() == 0xA0) // context-specific and constructed + tag number 0
			value = parser.parseAttributeAsBytes(0);

		return new OtherNameParseResult(typeId, value);
	}

	/**
	 * Parses a DER-encoded ASN.1 {@code UTF8String} to a Java string:
	 *
	 * @param str a DER-encoded byte array
	 * @return the converted Java string
	 * @throws NullPointerException     if {@code str} is {@code null}
	 * @throws IllegalArgumentException if {@code str} is empty or if the
	 *                                  DER-encoded byte array does not comply with
	 *                                  ASN.1 DER encoding rules
	 */
	public static String parseUtf8String(byte[] str) {
		Objects.requireNonNull(str, "str cannot be null");
		if (str.length == 0)
			throw new IllegalArgumentException("str cannot be empty");

		Asn1Parser parser = new Asn1Parser(str);

		parser.parseTag(UTF8STRING_TAG);
		int len = parser.parseLength();
		byte[] value = new byte[len];
		parser.parseBytes(value);

		return new String(value, StandardCharsets.UTF_8);
	}

}
