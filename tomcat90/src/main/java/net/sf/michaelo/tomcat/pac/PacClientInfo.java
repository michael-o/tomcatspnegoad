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

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/e465cb27-4bc1-4173-8be0-b5fd64dc9ff7">{@code PAC_CLIENT_INFO}</a>
 * structure from MS-PAC.
 */
public class PacClientInfo {

	private final String name;

	/**
	 * Parses a PAC client info object from a byte array.
	 *
	 * @param infoBytes
	 *            PAC client info structure encoded as bytes
	 * @throws NullPointerException
	 *             if {@code infoBytes} is null
	 * @throws IllegalArgumentException
	 *             if {@code infoBytes} is empty
	 */
	public PacClientInfo(byte[] infoBytes) {
		Objects.requireNonNull(infoBytes, "infoBytes cannot be null");
		if (infoBytes.length == 0)
			throw new IllegalArgumentException("infoBytes cannot be empty");

		PacDataBuffer buf = new PacDataBuffer(infoBytes);

		// ClientId
		buf.skip(8);
		// NameLength
		int nameLength = buf.getUnsignedShort();
		// Name
		byte[] dst = new byte[nameLength];
		buf.get(dst);
		this.name = new String(dst, StandardCharsets.UTF_16LE);
	}

	public String getName() {
		return name;
	}

}
