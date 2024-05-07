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

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399">{@code PAC_INFO_BUFFER}</a>
 * structure from MS-PAC.
 */
public class PacInfoBuffer {

	private final long type;
	private final long bufferSize;
	private final BigInteger offset;
	private final byte[] data;

	/**
	 * Constructs a PAC info buffer.
	 */
	public PacInfoBuffer(long type, long bufferSize, BigInteger offset, byte[] data) {
		this.type = type;
		this.bufferSize = bufferSize;
		this.offset = offset;
		this.data = data;
	}

	public long getType() {
		return type;
	}

	public long getBufferSize() {
		return bufferSize;
	}

	public BigInteger getOffset() {
		return offset;
	}

	public byte[] getData() {
		return data;
	}

}
