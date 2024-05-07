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
import java.security.Key;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962">{@code PAC Data}</a>
 * structure from MS-PAC. This implementation only parses the embedded structures which are required
 * for the purpose of this component, everything else is skipped.
 * <p>
 * <strong>Important:</strong> It is imperative to pass a suitable signature verifier implementation
 * and the long term Kerberos keys for the principal from the keytab which were used to establish
 * the security context. The simplest implementation is the {@link PrivateSunPacSignatureVerifier}
 * which uses private Sun classes to perform the calculation.
 */
public class Pac {

	private static final BigInteger EIGHT = BigInteger.valueOf(8L);

	private static final long KERB_VALIDATION_INFO = 0x00000001L;
	private static final long PAC_CLIENT_INFO = 0x0000000AL;
	private static final long UPN_DNS_INFO = 0x0000000CL;
	private static final long SERVER_SIGNATURE = 0x00000006L;
	private static final long KDC_SIGNATURE = 0x00000007L;

	protected final Log logger = LogFactory.getLog(getClass());

	private KerbValidationInfo kerbValidationInfo;
	private UpnDnsInfo upnDnsInfo;
	private PacClientInfo pacClientInfo;
	private PacSignatureData serverSignature;
	private PacSignatureData kdcSignature;

	private final PacSignatureVerifier signatureVerifier;
	private final byte[] zeroedPacData;

	/**
	 * Parses a PAC data object from a byte array.
	 *
	 * @param pacDataBytes
	 *            PAC data structure encoded as bytes
	 * @param signatureVerifier
	 *            a signature verifier implementation
	 * @throws NullPointerException
	 *             if {@code infoBytes} is null
	 * @throws IllegalArgumentException
	 *             if {@code infoBytes} is empty
	 * @throws NullPointerException
	 *             if {@code signatureVerifier} is null
	 * @throws IllegalArgumentException
	 *             if PAC version is not 0
	 * @throws IllegalArgumentException
	 *             if an embedded {@code PAC_INFO_BUFFER} structure offset is not a multiple of 8
	 * @throws IllegalArgumentException
	 *             if any embedded structure is invalid
	 * @throws IllegalArgumentException
	 *             if any of the required embedded structures ({@code KERB_VALIDATION_INFO},
	 *             {@code PAC_CLIENT_INFO}, {@code PAC_SIGNATURE_DATA} (Server Signature),
	 *             {@code PAC_SIGNATURE_DATA} (KDC Signature)) is not present
	 */
	public Pac(byte[] pacDataBytes, PacSignatureVerifier signatureVerifier) {
		Objects.requireNonNull(pacDataBytes, "pacDataBytes cannot be null");
		if (pacDataBytes.length == 0)
			throw new IllegalArgumentException("pacDataBytes cannot be empty");

		PacDataBuffer buf = new PacDataBuffer(pacDataBytes);
		this.signatureVerifier = Objects.requireNonNull(signatureVerifier,
				"signatureVerifier cannot be null");

		// Read PACTYPE structure
		if (logger.isTraceEnabled())
			logger.trace("Parsing PACTYPE structure...");
		// cBuffers
		long buffers = buf.getUnsignedInt();
		// Version
		long version = buf.getUnsignedInt();
		if (version != 0L)
			throw new IllegalArgumentException("PAC must have version 0, but has " + version);

		if (logger.isTraceEnabled())
			logger.trace("PAC has version " + version + " and contains " + buffers + " buffers");

		// Read PAC_INFO_BUFFER structures
		if (logger.isTraceEnabled())
			logger.trace("Parsing " + buffers + " PAC_INFO_BUFFER structures...");
		List<PacInfoBuffer> pacInfoBuffers = new ArrayList<>();
		for (long l = 0L; l < buffers; l++) {
			// ulType
			long type = buf.getUnsignedInt();
			// cbBufferSize
			long bufferSize = buf.getUnsignedInt();
			// Offset
			BigInteger offset = buf.getUnsignedLong();
			if (!offset.mod(EIGHT).equals(BigInteger.ZERO))
				throw new IllegalArgumentException(
						"PAC_INFO_BUFFER offset must be multiple of 8, but is " + offset);
			int pos = buf.position();
			buf.position(offset.intValue());
			byte[] data = new byte[(int) bufferSize];
			buf.get(data);
			buf.position(pos);
			if (logger.isTraceEnabled())
				logger.trace("PAC_INFO_BUFFER describes type " + String.format("0x%08X", type)
						+ " with size " + bufferSize + " and offset " + offset + " containing data "
						+ Base64.getEncoder().encodeToString(data));

			pacInfoBuffers.add(new PacInfoBuffer(type, bufferSize, offset, data));
		}

		zeroedPacData = Arrays.copyOf(pacDataBytes, pacDataBytes.length);

		for (PacInfoBuffer pacInfoBuffer : pacInfoBuffers) {
			long type = pacInfoBuffer.getType();
			byte[] data = pacInfoBuffer.getData();
			if (type == KERB_VALIDATION_INFO) {
				if (kerbValidationInfo != null) {
					if (logger.isTraceEnabled())
						logger.trace("Ignoring additional KERB_VALIDATION_INFO structure");
				} else {
					if (logger.isTraceEnabled())
						logger.trace("Parsing KERB_VALIDATION_INFO structure...");
					kerbValidationInfo = new KerbValidationInfo(data);
				}
			} else if (type == UPN_DNS_INFO) {
				if (upnDnsInfo != null) {
					if (logger.isTraceEnabled())
						logger.trace("Ignoring additional UPN_DNS_INFO structure");
				} else {
					if (logger.isTraceEnabled())
						logger.trace("Parsing UPN_DNS_INFO structure...");
					upnDnsInfo = new UpnDnsInfo(data);
				}
			} else if (type == PAC_CLIENT_INFO) {
				if (upnDnsInfo != null) {
					if (logger.isTraceEnabled())
						logger.trace("Ignoring additional PAC_CLIENT_INFO structure");
				} else {
					if (logger.isTraceEnabled())
						logger.trace("Parsing PAC_CLIENT_INFO structure...");
					pacClientInfo = new PacClientInfo(data);
				}
			} else if (type == SERVER_SIGNATURE) {
				if (serverSignature != null) {
					if (logger.isTraceEnabled())
						logger.trace(
								"Ignoring additional PAC_SIGNATURE_DATA (Server Signature) structure");
				} else {
					if (logger.isTraceEnabled())
						logger.trace("Parsing PAC_SIGNATURE_DATA (Server Signature) structure...");
					serverSignature = new PacSignatureData(data);
					int from = pacInfoBuffer.getOffset().intValue() + 4; // sizeof(SignatureType)
					int to = from + serverSignature.getType().getSize();
					Arrays.fill(zeroedPacData, from, to, (byte) 0);
				}
			} else if (type == KDC_SIGNATURE) {
				if (kdcSignature != null) {
					if (logger.isTraceEnabled())
						logger.trace(
								"Ignoring additional PAC_SIGNATURE_DATA (KDC Signature) structure");
				} else {
					if (logger.isTraceEnabled())
						logger.trace("Parsing PAC_SIGNATURE_DATA (KDC Signature) structure...");
					kdcSignature = new PacSignatureData(data);
					int from = pacInfoBuffer.getOffset().intValue() + 4; // sizeof(SignatureType)
					int to = from + kdcSignature.getType().getSize();
					Arrays.fill(zeroedPacData, from, to, (byte) 0);
				}
			} else {
				if (logger.isTraceEnabled())
					logger.trace(
							"Ignoring unsupported structure type " + String.format("0x%08X", type)
									+ " with data " + Base64.getEncoder().encodeToString(data));
			}
		}

		if (kerbValidationInfo == null)
			throw new IllegalArgumentException(
					"PAC does not contain required KERB_VALIDATION_INFO structure");

		if (pacClientInfo == null)
			throw new IllegalArgumentException(
					"PAC does not contain required PAC_CLIENT_INFO structure");

		if (serverSignature == null)
			throw new IllegalArgumentException(
					"PAC does not contain required PAC_SIGNATURE_DATA (Server Signature) structure");

		if (kdcSignature == null)
			throw new IllegalArgumentException(
					"PAC does not contain required PAC_SIGNATURE_DATA (KDC Signature) structure");
	}

	public KerbValidationInfo getKerbValidationInfo() {
		return kerbValidationInfo;
	}

	public UpnDnsInfo getUpnDnsInfo() {
		return upnDnsInfo;
	}

	public PacClientInfo getPacClientInfo() {
		return pacClientInfo;
	}

	public PacSignatureData getServerSignature() {
		return serverSignature;
	}

	public PacSignatureData getKdcSignature() {
		return kdcSignature;
	}

	/**
	 * Verifies the server signature of this PAC data structure with zeroed server and KDC signature
	 * values with the supplied long term Kerberos keys.
	 *
	 * @param keys
	 *            an array of long term Kerberos keys for the principal from the keytab which was
	 *            used to establish the security context
	 * @throws SignatureException
	 *             if the signature validation fails with all supplied keys
	 * @see PacSignatureVerifier
	 */
	public void verifySignature(Key[] keys) throws SignatureException {
		signatureVerifier.verify(serverSignature, zeroedPacData, keys);
	}

}
