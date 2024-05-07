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

import net.sf.michaelo.tomcat.realm.Sid;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1c0d6e11-6443-4846-b744-f9f810a504eb">{@code UPN_DNS_INFO}</a>
 * structure from MS-PAC.
 */
public class UpnDnsInfo {

	public final static long UPN_CONSTRUCTED_FLAG = 0x00000001L;
	public final static long SAM_NAME_AND_SID_FLAG = 0x00000002L;

	private final String upn;
	private final String dnsDomainName;

	private final long flags;

	private String samName;
	private Sid sid;

	/**
	 * Parses a UPN DNS info object from a byte array.
	 *
	 * @param infoBytes
	 *            UPN DNS info structure encoded as bytes
	 * @throws NullPointerException
	 *             if {@code infoBytes} is null
	 * @throws IllegalArgumentException
	 *             if {@code infoBytes} is empty
	 */
	public UpnDnsInfo(byte[] infoBytes) {
		Objects.requireNonNull(infoBytes, "infoBytes cannot be null");
		if (infoBytes.length == 0)
			throw new IllegalArgumentException("infoBytes cannot be empty");

		PacDataBuffer buf = new PacDataBuffer(infoBytes);

		// UpnLength
		int upnLength = buf.getUnsignedShort();
		// UpnOffset
		int upnOffset = buf.getUnsignedShort();
		// DnsDomainNameLength
		int dnsDomainNameLength = buf.getUnsignedShort();
		// DnsDomainNameOffset
		int dnsDomainNameOffset = buf.getUnsignedShort();
		// Flags
		/* Something isn't right, it appears to be that the bits are in reverse order
		 * or the documentation is wrong:
		 * - flag U should be at bit 31, but is at bit 0
		 * - flag S should be at bit 30, but is at bit 1
		 *
		 * Samba has the same reversed order: https://github.com/samba-team/samba/blob/9844ac289be3430fd3f72c5e57fa00e012c5d417/librpc/idl/krb5pac.idl#L93-L96
		 */
		this.flags = buf.getUnsignedInt();

		int pos = buf.position();
		buf.position(upnOffset);
		this.upn = getUnicodeString(buf, upnLength);
		buf.position(dnsDomainNameOffset);
		this.dnsDomainName = getUnicodeString(buf, dnsDomainNameLength);
		buf.position(pos);

		if ((flags & SAM_NAME_AND_SID_FLAG) != 0L) {
			// SamNameLength
			int samNameLength = buf.getUnsignedShort();
			// SamNameOffset
			int samNameOffset = buf.getUnsignedShort();
			// SidLength
			int sidLength = buf.getUnsignedShort();
			// SidOffset
			int sidOffset = buf.getUnsignedShort();

			pos = buf.position();
			buf.position(samNameOffset);
			this.samName = getUnicodeString(buf, samNameLength);
			byte[] dst = new byte[sidLength];
			buf.position(sidOffset);
			buf.get(dst);
			this.sid = new Sid(dst);
		}
	}

	public String getUpn() {
		return upn;
	}

	public String getDnsDomainName() {
		return dnsDomainName;
	}

	public long getFlags() {
		return flags;
	}

	public String getSamName() {
		return samName;
	}

	public Sid getSid() {
		return sid;
	}

	private String getUnicodeString(PacDataBuffer buf, int length) {
		byte[] dst = new byte[length];
		buf.get(dst);
		return new String(dst, StandardCharsets.UTF_16LE);
	}

}
