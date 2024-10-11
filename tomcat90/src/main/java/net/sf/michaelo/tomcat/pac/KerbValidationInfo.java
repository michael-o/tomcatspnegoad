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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import net.sf.michaelo.tomcat.realm.Sid;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73">{@code KERB_VALIDATION_INFO}</a>
 * structure from MS-PAC. This implementation only parses the members which are required for the
 * purpose of this component, everything else is skipped.
 */
public class KerbValidationInfo {

	public final static long EXTRA_SIDS_USER_FLAG = 0x00000020L;
	public final static long RESOURCE_GROUP_IDS_USER_FLAG = 0x00000200L;

	protected final Log logger = LogFactory.getLog(getClass());

	private final String effectiveName;
	private final String fullName;
	private final String logonScript;
	private final String profilePath;
	private final String homeDirectory;
	private final String homeDirectoryDrive;

	private final long userId;
	private final long primaryGroupId;
	private final List<GroupMembership> groupIds;

	private final long userFlags;

	private final String logonServer;
	private final String logonDomainName;
	private final Sid logonDomainId;

	private final long userAccountControl;

	private List<KerbSidAndAttributes> extraSids;

	private Sid resourceGroupDomainSid;
	private List<GroupMembership> resourceGroupIds;

	/**
	 * Parses a Kerberos validation info object from a byte array.
	 *
	 * @param infoBytes
	 *            Kerberos validation info structure encoded as bytes
	 * @throws NullPointerException
	 *             if {@code infoBytes} is null
	 * @throws IllegalArgumentException
	 *             if {@code infoBytes} is empty
	 * @throws IllegalArgumentException
	 *             if {@code GroupCount} is not equal to the actually marshaled group count
	 * @throws IllegalArgumentException
	 *             if {@code SidCount} is not zero, but flag D is not set in {@code UserFlags}
	 * @throws IllegalArgumentException
	 *             if {@code ExtraSids} is not {@code null}, but flag D is not set in {@code UserFlags}
	 * @throws IllegalArgumentException
	 *             if {@code SidCount} is not equal to the actually marshaled SID count
	 * @throws IllegalArgumentException
	 *             if {@code ResourceGroupDomainSid} is not {@code null}, but flag H is not set in
	 *             {@code UserFlags}
	 * @throws IllegalArgumentException
	 *             if {@code ResourceGroupCount} is not zero, but flag H is not set in
	 *             {@code UserFlags}
	 * @throws IllegalArgumentException
	 *             if {@code ResourceGroupIds} is not {@code null}, but flag H is not set in
	 *             {@code UserFlags}
	 * @throws IllegalArgumentException
	 *             if {@code ResourceGroupCount} is not equal to the actually marshaled resource
	 *             group count
	 * @throws IllegalArgumentException
	 *             if any {@code RPC_UNICODE_STRING} is incorrectly NDR-encoded
	 */
	public KerbValidationInfo(byte[] infoBytes) {
		Objects.requireNonNull(infoBytes, "infoBytes cannot be null");
		if (infoBytes.length == 0)
			throw new IllegalArgumentException("infoBytes cannot be empty");

		PacDataBuffer buf = new PacDataBuffer(infoBytes);

		// common RPC header
		buf.skip(8);
		// RPC type marshalling private header
		buf.skip(8);
		// RPC unique pointer
		long uniquePointer = buf.getUnsignedInt();
		logPointer("RPC unique", uniquePointer);

		// LogonTime
		buf.skip(8);
		// LogoffTime
		buf.skip(8);
		// KickOffTime
		buf.skip(8);
		// PasswordLastSet
		buf.skip(8);
		// PasswordCanChange
		buf.skip(8);
		// PasswordMustChange
		buf.skip(8);
		// EffectiveName
		RpcUnicodeString effectiveName = getRpcUnicodeString(buf);
		logPointer("effectiveName", effectiveName.getPointer());
		// FullName
		RpcUnicodeString fullName = getRpcUnicodeString(buf);
		logPointer("fullName", fullName.getPointer());
		// LogonScript
		RpcUnicodeString logonScript = getRpcUnicodeString(buf);
		logPointer("logonScript", logonScript.getPointer());
		// ProfilePath
		RpcUnicodeString profilePath = getRpcUnicodeString(buf);
		logPointer("profilePath", profilePath.getPointer());
		// HomeDirectory
		RpcUnicodeString homeDirectory = getRpcUnicodeString(buf);
		logPointer("homeDirectory", homeDirectory.getPointer());
		// HomeDirectoryDrive
		RpcUnicodeString homeDirectoryDrive = getRpcUnicodeString(buf);
		logPointer("homeDirectoryDrive", homeDirectoryDrive.getPointer());
		// LogonCount
		buf.skip(2);
		// BadPasswordCount
		buf.skip(2);
		// UserId
		this.userId = buf.getUnsignedInt();
		// PrimaryGroupId
		this.primaryGroupId = buf.getUnsignedInt();
		// GroupCount
		long groupCount = buf.getUnsignedInt();
		// GroupIds
		long groupIdsPointer = buf.getUnsignedInt();
		logPointer("groupIds", groupIdsPointer);
		// UserFlags
		/* Something isn't right, it appears to be that the bits are in reverse order
		 * or the documentation is wrong:
		 * - flag H should be at bit 22, but is at bit 9
		 * - flag D should be at bit 26, but is at bit 5
		 *
		 * Samba has the same reversed order: https://github.com/samba-team/samba/blob/9844ac289be3430fd3f72c5e57fa00e012c5d417/librpc/idl/netlogon.idl#L251-L263
		 */
		this.userFlags = buf.getUnsignedInt();
		// UserSessionKey
		buf.skip(16);
		// LogonServer
		RpcUnicodeString logonServer = getRpcUnicodeString(buf);
		logPointer("logonServer", logonServer.getPointer());
		// LogonDomainName
		RpcUnicodeString logonDomainName = getRpcUnicodeString(buf);
		logPointer("logonDomainName", logonDomainName.getPointer());
		// LogonDomainId
		long logonDomainIdPointer = buf.getUnsignedInt();
		logPointer("logonDomainId", logonDomainIdPointer);
		// Reserved1
		buf.skip(8);
		// UserAccountControl
		/*
		 * This is NOT userAccountControl from LDAP, see
		 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec
		 */
		this.userAccountControl = buf.getUnsignedInt();
		// SubAuthStatus
		buf.skip(4);
		// LastSuccessfulILogon
		buf.skip(8);
		// LastFailedILogon
		buf.skip(8);
		// FailedILogonCount
		buf.skip(4);
		// Reserved3
		buf.skip(4);
		// SidCount
		long sidCount = buf.getUnsignedInt();
		// ExtraSids
		long extraSidsPointer = buf.getUnsignedInt();
		logPointer("extraSids", extraSidsPointer);
		// ResourceGroupDomainSid
		long resourceGroupDomainSidPointer = buf.getUnsignedInt();
		logPointer("resourceGroupDomainSid", resourceGroupDomainSidPointer);
		// ResourceGroupCount
		long resourceGroupCount = buf.getUnsignedInt();
		// ResourceGroupIds
		long resourceGroupIdsPointer = buf.getUnsignedInt();
		logPointer("resourceGroupIds", resourceGroupIdsPointer);

		this.effectiveName = getNdrString(buf, effectiveName);
		this.fullName = getNdrString(buf, fullName);
		this.logonScript = getNdrString(buf, logonScript);
		this.profilePath = getNdrString(buf, profilePath);
		this.homeDirectory = getNdrString(buf, homeDirectory);
		this.homeDirectoryDrive = getNdrString(buf, homeDirectoryDrive);

		long actualGroupCount = buf.getUnsignedInt();
		if (groupCount != actualGroupCount)
			throw new IllegalArgumentException("GroupCount is " + groupCount
					+ ", but actual GroupCount is " + actualGroupCount);

		this.groupIds = new ArrayList<GroupMembership>();
		for (long l = 0L; l < groupCount; l++) {
			long relativeId = buf.getUnsignedInt();
			long attributes = buf.getUnsignedInt();
			this.groupIds.add(new GroupMembership(relativeId, attributes));
		}

		this.logonServer = getNdrString(buf, logonServer);
		this.logonDomainName = getNdrString(buf, logonDomainName);
		this.logonDomainId = getRpcSid(buf);

		if (sidCount != 0L && (userFlags & EXTRA_SIDS_USER_FLAG) == 0L)
			throw new IllegalArgumentException("SidCount is " + sidCount
					+ ", but flag D is not set in UserFlags (" + toHexString(userFlags) + ")");

		if (extraSidsPointer != 0L && (userFlags & EXTRA_SIDS_USER_FLAG) == 0L)
			throw new IllegalArgumentException("ExtraSids is not null ("
					+ toHexString(extraSidsPointer)
					+ "), but flag D is not set in UserFlags (" + toHexString(userFlags) + ")");


		// No need to check for UserFlags because the above tests make sure that flag D is set
		if (extraSidsPointer != 0L) {
			this.extraSids = new ArrayList<>();
			long actualSidCount = buf.getUnsignedInt();
			if (sidCount != actualSidCount)
				throw new IllegalArgumentException(
						"SidCount is " + sidCount + ", but actual SidCount is " + actualSidCount);
			long[] sidAttrs = new long[(int) sidCount];
			for (long l = 0L; l < sidCount; l++) {
				long extraSidPointer = buf.getUnsignedInt();
				long attributes = buf.getUnsignedInt();
				sidAttrs[(int) l] = attributes;
				logPointer("extraSid[" + l + "]", extraSidPointer);
			}
			for (long l = 0L; l < sidCount; l++) {
				Sid extraSid = getRpcSid(buf);
				this.extraSids.add(new KerbSidAndAttributes(extraSid, sidAttrs[(int) l]));
			}
		}

		if (resourceGroupDomainSidPointer != 0L && (userFlags & RESOURCE_GROUP_IDS_USER_FLAG) == 0L)
			throw new IllegalArgumentException("ResourceGroupDomainSid is not null ("
					+ toHexString(resourceGroupDomainSidPointer)
					+ "), but flag H is not set in UserFlags (" + toHexString(userFlags) + ")");

		if (resourceGroupCount != 0L && (userFlags & RESOURCE_GROUP_IDS_USER_FLAG) == 0L)
			throw new IllegalArgumentException("ResourceGroupCount is " + sidCount
					+ ", but flag H is not set in UserFlags (" + toHexString(userFlags) + ")");

		if (resourceGroupIdsPointer != 0L && (userFlags & RESOURCE_GROUP_IDS_USER_FLAG) == 0L)
			throw new IllegalArgumentException("ResourceGroupIds is not null ("
					+ toHexString(resourceGroupIdsPointer)
					+ "), but flag H is not set in UserFlags (" + toHexString(userFlags) + ")");

		// No need to check for UserFlags because the above tests make sure that flag H is set
		if (resourceGroupDomainSidPointer != 0L) {
			this.resourceGroupDomainSid = getRpcSid(buf);

			long actualResourceGroupCount = buf.getUnsignedInt();
			if (resourceGroupCount != actualResourceGroupCount)
				throw new IllegalArgumentException("ResourceGroupCount is " + resourceGroupCount
						+ ", but actual ResourceGroupCount is " + actualResourceGroupCount);

			// No need to check for UserFlags because the above tests make sure that flag H is set
			if (resourceGroupIdsPointer != 0L) {
				this.resourceGroupIds = new ArrayList<>();
				for (long l = 0L; l < resourceGroupCount; l++) {
					long relativeId = buf.getUnsignedInt();
					long attributes = buf.getUnsignedInt();
					this.resourceGroupIds.add(new GroupMembership(relativeId, attributes));
				}
			}
		}
	}

	public String getEffectiveName() {
		return effectiveName;
	}

	public String getFullName() {
		return fullName;
	}

	public String getLogonScript() {
		return logonScript;
	}

	public String getProfilePath() {
		return profilePath;
	}

	public String getHomeDirectory() {
		return homeDirectory;
	}

	public String getHomeDirectoryDrive() {
		return homeDirectoryDrive;
	}

	public long getUserId() {
		return userId;
	}

	public long getPrimaryGroupId() {
		return primaryGroupId;
	}

	public List<GroupMembership> getGroupIds() {
		return Collections.unmodifiableList(groupIds);
	}

	public long getUserFlags() {
		return userFlags;
	}

	public String getLogonServer() {
		return logonServer;
	}

	public String getLogonDomainName() {
		return logonDomainName;
	}

	public Sid getLogonDomainId() {
		return logonDomainId;
	}

	public long getUserAccountControl() {
		return userAccountControl;
	}

	public List<KerbSidAndAttributes> getExtraSids() {
		return extraSids != null ? Collections.unmodifiableList(extraSids) : extraSids;
	}

	public Sid getResourceGroupDomainSid() {
		return resourceGroupDomainSid;
	}

	public List<GroupMembership> getResourceGroupIds() {
		return resourceGroupIds != null ? Collections.unmodifiableList(resourceGroupIds)
				: resourceGroupIds;
	}

	private RpcUnicodeString getRpcUnicodeString(PacDataBuffer buf) {
		int length = buf.getUnsignedShort();
		int maximumLength = buf.getUnsignedShort();
		if (maximumLength % 2 == 1)
			maximumLength -= 1;
		long pointer = buf.getUnsignedInt();

		return new RpcUnicodeString(length, maximumLength, pointer);
	}

	/* See:
	 *  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ad703c18-564d-4238-a371-8d43cf442f81
	 *  - https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_04_02
	 */
	private String getNdrString(PacDataBuffer buf, RpcUnicodeString string) {
		long maximumCount = buf.getUnsignedInt();
		long offset = buf.getUnsignedInt();
		long actualCount = buf.getUnsignedInt();

		if (offset > maximumCount || actualCount > maximumCount - offset)
			throw new IllegalArgumentException(
					"Incorrectly NDR-encoded UNICODE_STRING: maximumCount: " + maximumCount
							+ ", offset: " + offset + ", actualCount: " + actualCount);

		if (maximumCount != string.getMaximumLength() / 2L
				|| actualCount != string.getLength() / 2L)
			throw new IllegalArgumentException(
					"NDR-encoded UNICODE_STRING does not match RPC_UNICODE_STRING: maximumCount: "
							+ maximumCount + ", actualCount: " + actualCount + ", maximumLength: "
							+ string.getMaximumLength() + ", length: " + string.getLength());

		buf.skip(2 * (int) offset);

		byte[] dst = new byte[2 * (int) actualCount];
		buf.get(dst);

		return new String(dst, StandardCharsets.UTF_16LE);
	}

	private Sid getRpcSid(PacDataBuffer buf) {
		long actualSubAuthorityCount = buf.getUnsignedInt();
		byte[] sidBytes = new byte[8 + (int) actualSubAuthorityCount * 4];
		buf.get(sidBytes);
		return new Sid(sidBytes);
	}

	private void logPointer(String name, long pointer) {
		if (logger.isTraceEnabled())
			logger.trace(name + " pointer: " + toHexString(pointer));
	}

	private String toHexString(long l) {
		return String.format("0x%08X", l);
	}

}
