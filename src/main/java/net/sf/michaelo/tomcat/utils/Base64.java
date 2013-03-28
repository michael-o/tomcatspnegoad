/*
 * Copyright 2013 Michael Osipov
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
package net.sf.michaelo.tomcat.utils;

/**
 * Base64 encoder/decoder.
 */
public final class Base64 {

	private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	private Base64() {
		// default private
	}

	/**
	 * Base-64 encodes the supplied block of data. Line wrapping is not applied on output.
	 *
	 * @param bytes
	 *            The block of data that is to be Base-64 encoded.
	 * @return A <code>String</code> containing the encoded data.
	 */
	public static String encode(final byte[] bytes) {
		int length = bytes.length;

		if (length == 0) {
			return "";
		}

		final StringBuilder buffer = new StringBuilder((int) Math.ceil(length / 3d) * 4);
		final int remainder = length % 3;
		length -= remainder;
		int block;
		int idx = 0;
		while (idx < length) {
			block = ((bytes[idx++] & 0xff) << 16) | ((bytes[idx++] & 0xff) << 8)
					| (bytes[idx++] & 0xff);
			buffer.append(ALPHABET.charAt(block >>> 18));
			buffer.append(ALPHABET.charAt((block >>> 12) & 0x3f));
			buffer.append(ALPHABET.charAt((block >>> 6) & 0x3f));
			buffer.append(ALPHABET.charAt(block & 0x3f));
		}
		if (remainder == 0) {
			return buffer.toString();
		}
		if (remainder == 1) {
			block = (bytes[idx] & 0xff) << 4;
			buffer.append(ALPHABET.charAt(block >>> 6));
			buffer.append(ALPHABET.charAt(block & 0x3f));
			buffer.append("==");
			return buffer.toString();
		}
		block = (((bytes[idx++] & 0xff) << 8) | ((bytes[idx]) & 0xff)) << 2;
		buffer.append(ALPHABET.charAt(block >>> 12));
		buffer.append(ALPHABET.charAt((block >>> 6) & 0x3f));
		buffer.append(ALPHABET.charAt(block & 0x3f));
		buffer.append("=");
		return buffer.toString();
	}

	/**
	 * Decodes the supplied Base-64 encoded string.
	 *
	 * @param string
	 *            The Base-64 encoded string that is to be decoded.
	 * @return A <code>byte[]</code> containing the decoded data block.
	 */
	public static byte[] decode(final String string) {
		final int length = string.length();
		if (length == 0) {
			return new byte[0];
		}

		final int pad = (string.charAt(length - 2) == '=') ? 2
				: (string.charAt(length - 1) == '=') ? 1 : 0;
		final int size = length * 3 / 4 - pad;
		byte[] buffer = new byte[size];
		int block;
		int idx = 0;
		int index = 0;
		while (idx < length) {
			block = (ALPHABET.indexOf(string.charAt(idx++)) & 0xff) << 18
					| (ALPHABET.indexOf(string.charAt(idx++)) & 0xff) << 12
					| (ALPHABET.indexOf(string.charAt(idx++)) & 0xff) << 6
					| (ALPHABET.indexOf(string.charAt(idx++)) & 0xff);
			buffer[index++] = (byte) (block >>> 16);
			if (index < size) {
				buffer[index++] = (byte) ((block >>> 8) & 0xff);
			}
			if (index < size) {
				buffer[index++] = (byte) (block & 0xff);
			}
		}
		return buffer;
	}
}
