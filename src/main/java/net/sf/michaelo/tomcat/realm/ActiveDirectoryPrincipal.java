/*
 * Copyright 2013 Michael Osipov
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

import java.io.Serializable;
import java.security.Principal;
import java.util.Collections;
import java.util.List;

import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.commons.lang3.ArrayUtils;
import org.ietf.jgss.GSSCredential;

/**
 * Represents a principal from Active Directory with a list of roles.
 * <p>
 * A Active Directory principal is comprised of the following items:
 * <ul>
 * <li>a Kerberos principal,</li>
 * <li>a distinguished name (DN) in the forest,</li>
 * <li>a security identifier (SID),</li>
 * <li>an optional GSS credential for credential delegation (impersonation),</li>
 * <li>and a list of roles ({@code memberOf}) the user has been assigned to. Only the common name
 * (CN) is stored.
 * </p>
 *
 * @version $Id$
 */
public class ActiveDirectoryPrincipal implements Principal, Serializable {

	private static final long serialVersionUID = 3096263076868974289L;

	private KerberosPrincipal principal;
	private String dn;
	private byte[] sid;
	private transient GSSCredential gssCredential;
	private List<String> roles;

	/**
	 * Constructs a new principal for the given parameters.
	 *
	 * @param principal
	 *            the underlying principal
	 * @param dn
	 *            TODO
	 * @param roles
	 *            the roles retrieved from Active Directory
	 */
	public ActiveDirectoryPrincipal(KerberosPrincipal principal, String dn, byte[] sid,
			GSSCredential gssCredential, List<String> roles) {
		this.principal = principal;
		this.dn = dn;
		this.sid = ArrayUtils.clone(sid);
		this.gssCredential = gssCredential;
		this.roles = Collections.unmodifiableList(roles);
	}

	/**
	 * Returns the underlying principal.
	 *
	 * @return the underlying principal
	 */
	public KerberosPrincipal getKerberosPrincipal() {
		return principal;
	}

	/**
	 * Grants access if supplied role is associated with this pricipal.
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

	@Override
	public String getName() {
		return principal.getName();
	}

	/**
	 * Returns the distinguished name of the principal.
	 *
	 * @return the distinguished name
	 */
	public String getDn() {
		return dn;
	}

	/**
	 * Return the security identifier (SID) of the principal.
	 *
	 * @return the
	 */
	public byte[] getSid() {
		return ArrayUtils.clone(sid);
	}

	@Override
	public int hashCode() {
		return principal.hashCode();
	}

	@Override
	public String toString() {
		return principal.toString();
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

}
