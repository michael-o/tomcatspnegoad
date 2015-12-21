/*
 * Copyright 2013–2016 Michael Osipov
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
 * An immutuable class representing a <a
 * href="https://msdn.microsoft.com/en-us/library/gg465313.aspx">security
 * identifier</a> from Active Directory.
 *
 * @version $Id$
 *
 */
public class Sid {
	private byte[] bytes;

	private byte revision;
	private byte subAuthorityCount;
	private byte[] identifierAuthority;
	private int[] subAuthorities;

	private String sidString;

	public Sid(byte[] sid) {
		this.bytes = Arrays.copyOf(sid, sid.length);

		ByteBuffer bb = ByteBuffer.wrap(this.bytes);
		bb.order(ByteOrder.LITTLE_ENDIAN);

		this.revision = bb.get();
		this.subAuthorityCount = bb.get();
		this.identifierAuthority = new byte[6];
		bb.get(this.identifierAuthority);

		StringBuilder sidStringBuilder = new StringBuilder("S");

		sidStringBuilder.append('-').append(this.revision);

		ByteBuffer iaBb = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
		iaBb.position(2);
		iaBb.put(this.identifierAuthority);
		iaBb.flip();

		sidStringBuilder.append('-').append(iaBb.getLong());

		this.subAuthorities = new int[this.subAuthorityCount];
		for (byte b = 0; b < this.subAuthorityCount; b++) {
			this.subAuthorities[b] = bb.getInt();

			sidStringBuilder.append('-').append(this.subAuthorities[b]);
		}

		this.sidString = sidStringBuilder.toString();
	}

	public byte[] getBytes() {
		return Arrays.copyOf(bytes, bytes.length);
	}

	@Override
	public String toString() {
		return sidString;
	}

}
