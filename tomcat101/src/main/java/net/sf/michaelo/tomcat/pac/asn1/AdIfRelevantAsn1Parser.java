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
package net.sf.michaelo.tomcat.pac.asn1;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.tomcat.util.buf.Asn1Parser;

import com.sun.security.jgss.AuthorizationDataEntry;

/**
 * A minimalist ASN.1 parser for Kerberos {@code AuthorizationData} according to RFC 4120, section
 * 5.2.6 for the {@code AD-IF-RELEVANT} type. It unwraps all nested data as described in <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/21181737-74fd-492c-bfbd-0322993a9061">MS-PAC
 * structure</a>.
 */
public class AdIfRelevantAsn1Parser {

	/*
	 * AD types as per: https://github.com/krb5/krb5-assignments/blob/master/ad-type
	 */
	public static final int AD_IF_RELEVANT = 1;
	public static final int AD_WIN2K_PAC = 128;

	private AdIfRelevantAsn1Parser() {
	}

	/**
	 * Parses the ASN.1 structure and converts to a list of {@code AuthorizationDataEntry} elements.
	 *
	 * @param adIfRelevant
	 *            ASN.1 encoded data
	 * @return a list of {@code AuthorizationDataEntry} elements
	 * @throws NullPointerException
	 *             if {@code adIfRelevant} is null
	 * @throws IllegalArgumentException
	 *             if {@code adIfRelevant} is empty
	 */
	public static List<AuthorizationDataEntry> parse(byte[] adIfRelevant) {
		Objects.requireNonNull(adIfRelevant, "adIfRelevant cannot be null");
		if (adIfRelevant.length == 0)
			throw new IllegalArgumentException("adIfRelevant cannot be empty");

		List<AuthorizationDataEntry> adEntries = new ArrayList<>();

		Asn1Parser parser = new Asn1Parser(adIfRelevant);
		parser.parseTagSequence();
		parser.parseFullLength();
		while (!parser.eof()) {
			parser.parseTagSequence();
			parser.parseLength();
			Asn1Parser p = new Asn1Parser(parser.parseAttributeAsBytes(0));
			BigInteger type = p.parseInt();
			p = new Asn1Parser(parser.parseAttributeAsBytes(1));
			byte[] data = p.parseOctetString();
			adEntries.add(new AuthorizationDataEntry(type.intValue(), data));
		}

		return adEntries;
	}

}
