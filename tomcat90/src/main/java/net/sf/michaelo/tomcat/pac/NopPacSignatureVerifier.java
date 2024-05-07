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
 * A PAC signature verifier which will do nothing.
 * <p>
 * <strong>Note:</strong> Use this verifier for testing purposes only, <em>do not</em> use in
 * production!
 */
public class NopPacSignatureVerifier implements PacSignatureVerifier {

	@Override
	public void verify(PacSignatureData signatureData, byte[] data, Key[] keys)
			throws SignatureException {
	}

}
