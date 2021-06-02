/*
 * Copyright 2013–2021 Michael Osipov
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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.catalina.TomcatPrincipal;
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
 * <li>the array of security groups the user has been assigned to, stored as SID strings (the actual
 * values are queried with {@code memberOf} and retrieved from {@code objectSid} and
 * {@code sIDHistory}),</li>
 * <li>and a map with additional attributes which are either a {@code String}, {@code byte[]} or a
 * {@code List} of either one.</li>
 * </ul>
 */
public class ActiveDirectoryPrincipal implements TomcatPrincipal {

	private final GSSName gssName;
	private final Sid sid;
	private final transient GSSCredential gssCredential;
	private final String[] roles;
	private final Map<String, Object> additionalAttributes;

	/**
	 * Constructs a new principal for the given parameters.
	 */
	public ActiveDirectoryPrincipal(GSSName gssName, Sid sid, GSSCredential gssCredential) {
		this(gssName, sid, null, gssCredential, null);
	}

	/**
	 * Constructs a new principal for the given parameters.
	 */
	public ActiveDirectoryPrincipal(GSSName gssName, Sid sid, List<String> roles,
			GSSCredential gssCredential, Map<String, Object> additionalAttributes) {
		this.gssName = gssName;
		this.sid = sid;
		if (roles == null || roles.isEmpty())
			this.roles = new String[0];
		else {
			this.roles = roles.toArray(new String[0]);
			Arrays.sort(this.roles);
		}
		this.gssCredential = gssCredential;
		if (additionalAttributes == null || additionalAttributes.isEmpty())
			this.additionalAttributes = Collections.emptyMap();
		else
			this.additionalAttributes = Collections.unmodifiableMap(additionalAttributes);
	}

	@Override
	public Principal getUserPrincipal() {
		return this;
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
	public GSSName getGssName() {
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

	@Override
	public GSSCredential getGssCredential() {
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
		if ("*".equals(role)) // Special 2.4 role meaning everyone
			return true;
		if (role == null)
			return false;
		return Arrays.binarySearch(roles, role) >= 0;
	}

	/**
	 * Returns the role SID strings of the given principal.
	 *
	 * @return a read-only view of the roles
	 */
	public String[] getRoles() {
		return Arrays.copyOf(roles, roles.length);
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
		if (obj == null)
			return false;

		if (!(obj instanceof ActiveDirectoryPrincipal))
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

	@Override
	public void logout() throws Exception {
		if (gssCredential != null) {
			gssCredential.dispose();
		}
	}

}
