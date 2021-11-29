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
package net.sf.michaelo.tomcat.asn1;

import java.security.cert.CertificateParsingException;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;
import org.junit.Test;

import net.sf.michaelo.tomcat.realm.asn1.OtherNameAsn1Parser;
import net.sf.michaelo.tomcat.realm.asn1.OtherNameParseResult;

public class OtherNameAsn1ParserTest {

	@Test(expected = NullPointerException.class)
	public void testNullUtf8String() throws Exception {
		OtherNameAsn1Parser.parseUtf8String(null);
	}

	@Test
	public void testEmptyUtf8String() {
		try {
			OtherNameAsn1Parser.parseUtf8String(new byte[0]);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.equalTo("string type tag not available, buffer is empty"));
		}
	}

	@Test
	public void testNotStartingUtf8String() {
		byte[] otherName = { (byte) 0x13 };

		try {
			OtherNameAsn1Parser.parseUtf8String(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("string must start with a UTF8String tag, but starts with"));
		}
	}

	@Test
	public void testTwoByteLengthUtf8String() {
		byte[] otherName = { (byte) 0x0C, (byte) 0x81, (byte) 0x80 };

		try {
			OtherNameAsn1Parser.parseUtf8String(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("UTF8String length (128 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testZeroLengthUtf8String() throws Exception {
		byte[] otherName = { (byte) 0x0C, (byte) 0x00 };

		String utf8String = OtherNameAsn1Parser.parseUtf8String(otherName);
		MatcherAssert.assertThat(utf8String, CoreMatchers.equalTo(""));
	}

	@Test
	public void testUtf8String() throws Exception {
		byte[] otherName = { (byte) 0x0C, (byte) 0x0A, (byte) 0xD0, (byte) 0x94, (byte) 0xD0, (byte) 0xB6, (byte) 0xD0,
				(byte) 0xB0, (byte) 0xD0, (byte) 0xB2, (byte) 0xD0, (byte) 0xB0 };

		String utf8String = OtherNameAsn1Parser.parseUtf8String(otherName);
		MatcherAssert.assertThat(utf8String, CoreMatchers.equalTo("Джава"));
	}

	@Test(expected = NullPointerException.class)
	public void testNullOtherName() throws Exception {
		OtherNameAsn1Parser.parse(null);
	}

	@Test
	public void testEmptyOtherName() {
		try {
			OtherNameAsn1Parser.parse(new byte[0]);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.equalTo("otherName type tag not available, buffer is empty"));
		}
	}

	@Test
	public void testNotStartingSequence() {
		byte[] otherName = { (byte) 0x31 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("otherName must start with a SEQUENCE tag, but starts with "));
		}
	}

	@Test
	public void testNullLength() {
		byte[] otherName = { (byte) 0x30 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.equalTo("Type length not available, buffer is empty"));
		}
	}

	@Test
	public void testIndefiniteLength() {
		byte[] otherName = { (byte) 0x30, (byte) 0x80 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.equalTo("Indefinite type length is not supported"));
		}
	}

	@Test
	public void testMoreThanTwoByteLength() {
		byte[] otherName = { (byte) 0x30, (byte) 0x83 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.equalTo("Type length above 64 KiB ist not supported"));
		}
	}

	@Test
	public void testTwoByteLength1() {
		byte[] otherName = { (byte) 0x30, (byte) 0x82 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("Type length bytes (2 B) are larger than the buffer offers"));
		}
	}

	@Test
	public void testTwoByteLength2() {
		byte[] otherName = { (byte) 0x30, (byte) 0x81, (byte) 0x80 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("SEQUENCE length (128 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testHalfByteLength() {
		byte[] otherName = { (byte) 0x30, (byte) 0x7F };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("SEQUENCE length (127 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testThreeByteLength1() {
		byte[] otherName = { (byte) 0x30, (byte) 0x82, (byte) 0xFF, (byte) 0x7F };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("SEQUENCE length (65407 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testThreeByteLength2() {
		byte[] otherName = { (byte) 0x30, (byte) 0x82, (byte) 0xFF, (byte) 0xFF };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("SEQUENCE length (65535 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testParseNullOid() {
		byte[] otherName = { (byte) 0x30, (byte) 0x00 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.equalTo("otherName fields not available, buffer is empty"));
		}
	}

	@Test
	public void testParseZeroLengthOid() {
		byte[] otherName = { (byte) 0x30, (byte) 0x02, (byte) 0x06, (byte) 0x00 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.equalTo("OID value not available, buffer is empty"));
		}
	}

	@Test
	public void testParseNotStartingOid() {
		byte[] otherName = { (byte) 0x30, (byte) 0x02, (byte) 0x05, (byte) 0x00 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("OID must start with an OBJECT IDENTIFIER tag, but is"));
		}
	}

	@Test
	public void testParseInvalidOidLength() {
		byte[] otherName = { (byte) 0x30, (byte) 0x03, (byte) 0x06, (byte) 0x05, (byte) 0x01 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("OBJECT IDENTIFIER length (5 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testParseTruncatedOidLength() {
		byte[] otherName = { (byte) 0x30, (byte) 0x04 /* here is 1 B missing */, (byte) 0x06, (byte) 0x03, (byte) 0x01,
				(byte) 0x01, (byte) 0x01 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("OBJECT IDENTIFIER length (3 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testParseNullValue() {
		byte[] otherName = { (byte) 0x30, (byte) 0x03, (byte) 0x06, (byte) 0x01, (byte) 0x01 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.equalTo("Value type tag not available, buffer is empty"));
		}
	}

	@Test
	public void testParseUniversalTagValue() {
		byte[] otherName = { (byte) 0x30, (byte) 0x04, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0x0C };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.equalTo("Value must be explicitly encoded"));
		}
	}

	@Test
	public void testParseConstructedTagValue() {
		byte[] otherName = { (byte) 0x30, (byte) 0x04, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) (0x0C | 0x10) };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.equalTo("Value must be explicitly encoded"));
		}
	}

	@Test
	public void testParseContextSpecificTagValue() {
		byte[] otherName = { (byte) 0x30, (byte) 0x04, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) (0x0C | 0x80) };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.equalTo("Value must be explicitly encoded"));
		}
	}

	@Test
	public void testParseWrongTagNumberInValue() {
		byte[] otherName = { (byte) 0x30, (byte) 0x04, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA1 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.startsWith("Value tag number must be 0, but is"));
		}
	}

	@Test
	public void testParseInvalidConstructedValue() {
		byte[] otherName = { (byte) 0x30, (byte) 0x05, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0,
				(byte) 0x02 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("Value length (2 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testParseInvalidConstructedValue2() {
		byte[] otherName = { (byte) 0x30, (byte) 0x05, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x00,
				(byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.equalTo("Value not available, buffer is empty"));
		}
	}

	@Test
	public void testParseInvalidConstructedValue3() {
		byte[] otherName = { (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x06,
				(byte) 0xA0, (byte) 0x05, (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("Value length (5 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testParseInvalidConstructedValue4() throws Exception {
		byte[] otherName = { (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x07,
				(byte) 0xA0, (byte) 0x04, (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
		Assert.assertArrayEquals(new byte[] { 0x01 }, result.getTypeId());
		Assert.assertArrayEquals(new byte[] { (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E' }, result.getValue());
	}

	@Test
	public void testParseInvalidConstructedValue5() {
		byte[] otherName = { (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x07,
				(byte) 0xA0, (byte) 0x00, (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.equalTo("Value not available, buffer is empty"));
		}
	}

	@Test
	public void testParseOtherName() throws Exception {
		byte[] otherName = { (byte) 0x30, (byte) 0x0A, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x05,
				(byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
		Assert.assertArrayEquals(new byte[] { 0x01 }, result.getTypeId());
		Assert.assertArrayEquals(new byte[] { (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' },
				result.getValue());
	}

	@Test
	public void testParseConstructedTagValueJDK6776681() throws Exception {
		byte[] otherName = { (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x07,
				(byte) (0xC | 0x10), (byte) 0x05, (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
		Assert.assertArrayEquals(new byte[] { 0x01 }, result.getTypeId());
		Assert.assertArrayEquals(new byte[] { (byte) (0xC | 0x10), (byte) 0x05, (byte) 0x0C, (byte) 0x03, (byte) 'Y',
				(byte) 'E', (byte) 'S' }, result.getValue());
	}

	@Test
	public void testParseContextSpecificTagValueJDK6776681() throws Exception {
		byte[] otherName = { (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x07,
				(byte) (0xC | 0x80), (byte) 0x05, (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
		Assert.assertArrayEquals(new byte[] { 0x01 }, result.getTypeId());
		Assert.assertArrayEquals(new byte[] { (byte) (0xC | 0x80), (byte) 0x05, (byte) 0x0C, (byte) 0x03, (byte) 'Y',
				(byte) 'E', (byte) 'S' }, result.getValue());
	}

	@Test
	public void testParseWrongTagNumberValueJDK6776681() throws Exception {
		byte[] otherName = { (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x07,
				(byte) 0xA1, (byte) 0x05, (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
		Assert.assertArrayEquals(new byte[] { 0x01 }, result.getTypeId());
		Assert.assertArrayEquals(
				new byte[] { (byte) 0xA1, (byte) 0x05, (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' },
				result.getValue());
	}

	@Test
	public void testParseInvalidConstructedValueJDK6776681() {
		byte[] otherName = { (byte) 0x30, (byte) 0x07, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x02,
				(byte) 0xA0, (byte) 0x02 };

		try {
			OtherNameAsn1Parser.parse(otherName);
			Assert.fail("Exception expected");
		} catch (CertificateParsingException e) {
			MatcherAssert.assertThat(e.getMessage(),
					CoreMatchers.startsWith("Value length (2 B) is larger than the buffer offers"));
		}
	}

	@Test
	public void testParseOtherNameJDK6776681() throws Exception {
		byte[] otherName = { (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xA0, (byte) 0x07,
				(byte) 0xA0, (byte) 0x05, (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' };

		OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
		Assert.assertArrayEquals(new byte[] { 0x01 }, result.getTypeId());
		Assert.assertArrayEquals(new byte[] { (byte) 0x0C, (byte) 0x03, (byte) 'Y', (byte) 'E', (byte) 'S' },
				result.getValue());
	}

	@Test
	public void testParseOtherNameLongSequence() throws Exception {
		byte[] otherName = { (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x06, (byte) 0x64, (byte) 0x02,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0xA0, (byte) 0x81, (byte) 0x98, (byte) 0xA0, (byte) 0x81,
				(byte) 0x95, (byte) 0x0C, (byte) 0x81, (byte) 0x92, (byte) 'Y', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'S' };

		OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
		byte[] typeId = result.getTypeId();
		Assert.assertEquals(100, typeId.length);
		Assert.assertEquals(2, typeId[0]);
		Assert.assertEquals(2, typeId[typeId.length - 1]);
		byte[] value = result.getValue();
		Assert.assertEquals(149, value.length);
		String str = OtherNameAsn1Parser.parseUtf8String(value);
		Assert.assertEquals(
				"YEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEES",
				str);
	}

	@Test
	public void testParseOtherNameLongSequenceJDK6776681() throws Exception {
		byte[] otherName = { (byte) 0x30, (byte) 0x81, (byte) 0xFE, (byte) 0x06, (byte) 0x64, (byte) 0x02, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
				(byte) 0x01, (byte) 0x02, (byte) 0xA0, (byte) 0x81, (byte) 0x95, (byte) 0x0C, (byte) 0x81, (byte) 0x92,
				(byte) 'Y', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E', (byte) 'E',
				(byte) 'E', (byte) 'S' };

		OtherNameParseResult result = OtherNameAsn1Parser.parse(otherName);
		byte[] typeId = result.getTypeId();
		Assert.assertEquals(100, typeId.length);
		Assert.assertEquals(2, typeId[0]);
		Assert.assertEquals(2, typeId[typeId.length - 1]);
		byte[] value = result.getValue();
		Assert.assertEquals(149, value.length);
		String str = OtherNameAsn1Parser.parseUtf8String(value);
		Assert.assertEquals(
				"YEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEES",
				str);
	}

}
