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

import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * A thin wrapper around {@link ByteBuffer} to comply with the encoding rules defined by the
 * <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6655b92f-ab06-490b-845d-037e6987275f">{@code PACTYPE}</a>
 * structure from MS-PAC.
 */
public class PacDataBuffer {

	private static final BigInteger TWO_COMPL_REF = BigInteger.ONE.shiftLeft(64);

	private final ByteBuffer buf;

	/**
	 * Constructs a PAC data buffer from a byte array.
	 *
	 * @param pacDataBytes
	 *            PAC data encoded as bytes
	 */
	public PacDataBuffer(byte[] pacDataBytes) {
		buf = ByteBuffer.wrap(pacDataBytes);
		buf.order(ByteOrder.LITTLE_ENDIAN);
	}

	public int position() {
		return ((Buffer) buf).position();
	}

	public PacDataBuffer position(int newPosition) {
		((Buffer) buf).position(newPosition);
		return this;
	}

	public PacDataBuffer skip(int bytes) {
		((Buffer) buf).position(buf.position() + bytes);
		return this;
	}

	protected PacDataBuffer align(int bytes) {
		int shift = ((Buffer) buf).position() & bytes - 1;
		if (bytes != 0 && shift != 0)
			skip(bytes - shift);
		return this;
	}

	public PacDataBuffer get(byte[] dst) {
		buf.get(dst);
		return this;
	}

	public int getInt() {
		align(4);
		return buf.getInt();
	}

	public int getUnsignedShort() {
		align(2);
		return buf.getShort() & 0xffff;
	}

	public long getUnsignedInt() {
		align(4);
		return buf.getInt() & 0xffffffffL;
	}

	public BigInteger getUnsignedLong() {
		align(8);
		long temp = buf.getLong();
		BigInteger value = BigInteger.valueOf(temp);
		if (value.compareTo(BigInteger.ZERO) < 0)
			value = value.add(TWO_COMPL_REF);
		return value;
	}

}
