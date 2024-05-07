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

import java.security.Key;
import java.security.SignatureException;

/**
 * An interface for pluggable PAC signature verifier implementations for {@link PacSignatureData}.
 * <p>
 * The specification of Kerberos checksum (calculation) is available at
 * <ul>
 * <li><a href="https://datatracker.ietf.org/doc/html/rfc4120#section-4">RFC 4120, section 4</a></li>
 * <li><a href="https://www.rfc-editor.org/rfc/rfc4757.html#section-4">RFC 4757, section 4</a></li>
 * <li><a href="https://datatracker.ietf.org/doc/html/rfc3961">RFC 3961</a></li>
 * <li><a href="https://www.rfc-editor.org/rfc/rfc3962.html">RFC 9362</a></li>
 * </ul>
 */
public interface PacSignatureVerifier {

	/* Key usage as per:
	 * - https://github.com/krb5/krb5-assignments/blob/master/key-usage
	 * - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/a194aa34-81bd-46a0-a931-2e05b87d1098
	 */
	int KU_KERB_NON_KERB_CKSUM_SALT = 17;

	/**
	 * Verifies the signature on the supplied data with an array of suitable Kerberos keys.
	 *
	 * @param signatureData
	 *            the PAC signature data to be verified
	 * @param data
	 *            the data to be verififed
	 * @param keys
	 *            an array of keys to calculate the signature
	 * @throws NullPointerException
	 *             if any argument is null
	 * @throws IllegalArgumentException
	 *             if any array is empty
	 * @throws IllegalArgumentException
	 *             if no key algorithm matches the {@link PacSignatureData.SignatureType#getEType()
	 *             signature encryption type}
	 * @throws SignatureException
	 *             if signature cannot be verified
	 */
	void verify(PacSignatureData signatureData, byte[] data, Key[] keys) throws SignatureException;

}
