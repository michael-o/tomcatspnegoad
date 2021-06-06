/*
 * Copyright 2013–2021 Michael Osipov
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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * An immutable class representing a
 * <a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861">security identifier</a>
 * from Active Directory.
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

	public Sid(byte[] sid) {
		if (sid == null)
			throw new NullPointerException("SID cannot be null");

		if (sid.length < 12)
			throw new IllegalArgumentException(
					"SID must be at least 12 bytes long but is " + sid.length);

		this.bytes = Arrays.copyOf(sid, sid.length);

		ByteBuffer bb = ByteBuffer.wrap(this.bytes);
		bb.order(ByteOrder.LITTLE_ENDIAN);

		// Always 0x01
		this.revision = bb.get() & 0xFF;
		if (this.revision != 0x01)
			throw new IllegalArgumentException(
					"SID revision must be 1 but is " + this.revision);

		// At most 15 subauthorities
		this.subAuthorityCount = bb.get() & 0xFF;
		if (this.subAuthorityCount > 15)
			throw new IllegalArgumentException(
					"SID sub authority count must be at most 15 but is " + this.subAuthorityCount);

		this.identifierAuthority = new byte[6];
		bb.get(this.identifierAuthority);

		StringBuilder sidStringBuilder = new StringBuilder("S");

		sidStringBuilder.append('-').append(this.revision);

		ByteBuffer iaBb = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
		iaBb.position(2);
		iaBb.put(this.identifierAuthority);
		iaBb.flip();

		sidStringBuilder.append('-').append(iaBb.getLong());

		this.subAuthorities = new long[this.subAuthorityCount];
		for (byte b = 0; b < this.subAuthorityCount; b++) {
			this.subAuthorities[b] = bb.getInt() & 0xffffffffL;

			sidStringBuilder.append('-').append(this.subAuthorities[b]);
		}

		this.sidString = sidStringBuilder.toString();
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
