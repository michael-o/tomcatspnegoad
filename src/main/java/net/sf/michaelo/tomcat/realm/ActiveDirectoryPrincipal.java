/*
 * Copyright 2013–2016 Michael Osipov
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

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;

/**
 * Represents a principal from Active Directory with a list of roles.
 * <p>
 * An Active Directory principal is comprised of the following items:
 * <ul>
 * <li>the GSS name,</li>
 * <li>the security identifier (SID),</li>
 * <li>an optional GSS credential for credential delegation (impersonation),</li>
 * <li>the list of security groups the user has been assigned to, stored as SID strings (the actual
 * value(s) are queried with {@code memberOf} and stored from {@code objectSid} and
 * {@code sIDHistory}),</li>
 * <li>and a map with additional attributes.</li>
 * </ul>
 *
 * </p>
 *
 * @version $Id$
 */
public class ActiveDirectoryPrincipal implements Principal {

	private final GSSName gssName;
	private final Sid sid;
	private final GSSCredential gssCredential;
	private final List<String> roles;
	private final Map<String, Object> additionalAttributes;

	/**
	 * Constructs a new principal for the given parameters.
	 *
	 * @param gssName
	 *            the underlying GSS name
	 * @param roles
	 *            the roles retrieved from Active Directory
	 */
	public ActiveDirectoryPrincipal(GSSName gssName, Sid sid, GSSCredential gssCredential,
			List<String> roles, Map<String, Object> additionalAttributes) {
		this.gssName = gssName;
		this.sid = sid;
		this.gssCredential = gssCredential;
		this.roles = Collections.unmodifiableList(roles);
		this.additionalAttributes = Collections.unmodifiableMap(additionalAttributes);
	}

	@Override
	public String getName() {
		return gssName.toString();
	}

	/**
	 * Returns the underlying GSS name.
	 *
	 * @return the underlying GSS name
	 */
	public GSSName getGSSName() {
		return gssName;
	}

	/**
	 * Returns the security identifier (SID) of the principal.
	 *
	 * @return the security identifier
	 */
	public Sid getSid() {
		return sid;
	}

	/**
	 * Returns the delegated credential if the server is trusted for delegation and the credential
	 * was intended to be stored.
	 *
	 * @return the delegated credential
	 */
	public GSSCredential getDelegatedCredential() {
		return gssCredential;
	}

	/**
	 * Grants access if supplied role is associated with this principal.
	 *
	 * @param role
	 *            the role to check
	 * @return true if principal is associated with the role, else false
	 */
	public boolean hasRole(String role) {

		if (role == null)
			return false;
		if (role.equals("*"))
			return true;
		return roles.contains(role);
	}

	/**
	 * Holds additional attributes for a given principal which may be stored in Active Directory.
	 *
	 * @return a read-only view of the additional attributes
	 */
	public Map<String, Object> getAdditionalAttributes() {
		return additionalAttributes;
	}

	@Override
	public boolean equals(Object obj) {
		if(obj == null)
			return false;

		if(!(obj instanceof ActiveDirectoryPrincipal))
			return false;

		ActiveDirectoryPrincipal other = (ActiveDirectoryPrincipal) obj;

		return gssName.equals((Object) other.gssName);
	}

	@Override
	public int hashCode() {
		return gssName.hashCode();
	}

	@Override
	public String toString() {
		return gssName.toString();
	}

}
