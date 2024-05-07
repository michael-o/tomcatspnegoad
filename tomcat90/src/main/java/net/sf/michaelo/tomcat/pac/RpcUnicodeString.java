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

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/94a16bb6-c610-4cb9-8db6-26f15f560061">{@code RPC_UNICODE_STRING}</a>
 * structure from MS-DTYP.
 */
public class RpcUnicodeString {

	private long length;
	private long maximumLength;
	private long pointer;

	/**
	 * Constructs a RPC Unicode string.
	 *
	 * @throws IllegalArgumentException
	 *             if {@code maximumLength} is smaller than {@code length}
	 */
	public RpcUnicodeString(long length, long maximumLength, long pointer) {
		if (maximumLength < length)
			throw new IllegalArgumentException(
					"RPC_UNICODE_STRING maximumLength is smaller than length: " + maximumLength
							+ " < " + length);

		this.length = length;
		this.maximumLength = maximumLength;
		this.pointer = pointer;
	}

	public long getLength() {
		return length;
	}

	public long getMaximumLength() {
		return maximumLength;
	}

	public long getPointer() {
		return pointer;
	}

}
