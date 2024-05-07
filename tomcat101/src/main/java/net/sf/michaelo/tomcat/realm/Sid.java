/*
 * Copyright 2013–2024 Michael Osipov
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

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * A class representing a <a href=
 * "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861">{@code SID}
 * (security identifier)</a> from MS-DTYP.
 */
public class Sid {

	public static final Sid NULL_SID = new Sid(new byte[] { (byte) 0x01, (byte) 0x01, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00 });

	public static final Sid ANONYMOUS_SID = new Sid(new byte[] { (byte) 0x01, (byte) 0x01,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x05,
			(byte) 0x07, (byte) 0x00, (byte) 0x00, (byte) 0x00 });

	private byte[] bytes;

	private int revision;
	private int subAuthorityCount;
	private byte[] identifierAuthority;
	private long[] subAuthorities;

	private String sidString;

	/**
	 * Parses a SID object from a byte array.
	 *
	 * @param sidBytes
	 *            SID structure encoded as bytes
	 * @throws NullPointerException
	 *             if {@code sidBytes} is null
	 * @throws IllegalArgumentException
	 *             if {@code sidBytes} contains less than 12 bytes
	 * @throws IllegalArgumentException
	 *             if SID's revision is not 1
	 * @throws IllegalArgumentException
	 *             if SID's subauthority count is more than 15
	 */
	public Sid(byte[] sidBytes) {
		if (sidBytes == null)
			throw new NullPointerException("sidBytes cannot be null");
		if (sidBytes.length < 12)
			throw new IllegalArgumentException(
					"SID must be at least 12 bytes long but is " + sidBytes.length);

		ByteBuffer buf = ByteBuffer.wrap(sidBytes);
		buf.order(ByteOrder.LITTLE_ENDIAN);

		// Always 0x01
		this.revision = buf.get() & 0xFF;
		if (this.revision != 0x01)
			throw new IllegalArgumentException("SID revision must be 1 but is " + this.revision);

		// At most 15 subauthorities
		this.subAuthorityCount = buf.get() & 0xFF;
		if (this.subAuthorityCount > 15)
			throw new IllegalArgumentException(
					"SID subauthority count must be at most 15 but is " + this.subAuthorityCount);

		this.identifierAuthority = new byte[6];
		buf.get(this.identifierAuthority);

		StringBuilder sidStringBuilder = new StringBuilder("S");

		sidStringBuilder.append('-').append(this.revision);

		ByteBuffer iaBuf = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
		((Buffer) iaBuf).position(2);
		iaBuf.put(this.identifierAuthority);
		((Buffer) iaBuf).flip();

		sidStringBuilder.append('-').append(iaBuf.getLong());

		this.subAuthorities = new long[this.subAuthorityCount];
		for (byte b = 0; b < this.subAuthorityCount; b++) {
			this.subAuthorities[b] = buf.getInt() & 0xffffffffL;

			sidStringBuilder.append('-').append(this.subAuthorities[b]);
		}

		this.bytes = Arrays.copyOf(sidBytes, sidBytes.length);
		this.sidString = sidStringBuilder.toString();
	}

	public Sid append(long relativeId) {
		byte[] sidBytes = this.bytes;
		byte[] appendedSidBytes = new byte[sidBytes.length + 4];
		System.arraycopy(sidBytes, 0, appendedSidBytes, 0, sidBytes.length);
		appendedSidBytes[1] = (byte) (this.subAuthorityCount + 1);
		int signedRelativeId = (int) (relativeId);
		appendedSidBytes[sidBytes.length + 0] = (byte) (signedRelativeId & 0xFF);
		appendedSidBytes[sidBytes.length + 1] = (byte) ((signedRelativeId >> 8) & 0xFF);
		appendedSidBytes[sidBytes.length + 2] = (byte) ((signedRelativeId >> 16) & 0xFF);
		appendedSidBytes[sidBytes.length + 3] = (byte) ((signedRelativeId >> 24) & 0xFF);
		return new Sid(appendedSidBytes);
	}

	public byte[] getBytes() {
		return Arrays.copyOf(bytes, bytes.length);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;

		if (!(obj instanceof Sid))
			return false;

		Sid that = (Sid) obj;

		if (this == that)
			return true;

		return Arrays.equals(this.bytes, that.bytes);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(this.bytes);
	}

	@Override
	public String toString() {
		return sidString;
	}

}
