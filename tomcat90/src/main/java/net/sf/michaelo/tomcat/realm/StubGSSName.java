/*
 * Copyright 2021 Michael Osipov
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

import java.util.Objects;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * Stub GSS name implementation to merely transport a name with its string name type. This class is not intended to be
 * used in real with the {@link GSSManager}.
 */
public class StubGSSName implements GSSName {

	private final String name;
	private final Oid oid;

	public StubGSSName(String name, Oid oid) {
		this.name = name;
		this.oid = oid;
	}

	@Override
	public boolean equals(GSSName another) throws GSSException {
		if (another instanceof StubGSSName) {
			StubGSSName stubGssName = (StubGSSName) another;
			return Objects.equals(name, stubGssName.name) && Objects.equals(oid, stubGssName.oid);
		}

		return false;
	}

	/**
	 * @throws UnsupportedOperationException
	 *             always throws because not implemented
	 */
	@Override
	public GSSName canonicalize(Oid mech) throws GSSException {
		throw new UnsupportedOperationException("method canonicalize() is not supported");
	}

	/**
	 * @throws UnsupportedOperationException
	 *             always throws because not implemented
	 */
	@Override
	public byte[] export() throws GSSException {
		throw new UnsupportedOperationException("method export() is not supported");
	}

	@Override
	public Oid getStringNameType() throws GSSException {
		return oid;
	}

	/**
	 * @throws UnsupportedOperationException
	 *             always throws because not implemented
	 */
	@Override
	public boolean isAnonymous() {
		throw new UnsupportedOperationException("method isAnonymous() is not supported");
	}

	/**
	 * @throws UnsupportedOperationException
	 *             always throws because not implemented
	 */
	@Override
	public boolean isMN() {
		throw new UnsupportedOperationException("method isNM() is not supported");
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object another) {
		if (another instanceof GSSName)
			try {
				return equals((GSSName) another);
			} catch (GSSException e) {
				; // Ignore
			}

		return false;
	}

	@Override
	public String toString() {
		return name;
	}

}
