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

import javax.naming.ldap.LdapName;

import org.apache.commons.lang3.ArrayUtils;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * Represents a principal from Active Directory with a list of roles.
 * <p>
 * An Active Directory principal is comprised of the following items:
 * <ul>
 * <li>a GSS name,</li>
 * <li>a mechanism OID with which the authentication has been performed,</li>
 * <li>a security identifier (SID),</li>
 * <li>a distinguished name (DN) in the forest,</li>
 * <li>an optional GSS credential for credential delegation (impersonation),</li>
 * <li>and a list of roles ({@code memberOf}) the user has been assigned to. Only the common name
 * (CN) is stored.
 * </ul>
 * </p>
 *
 * @version $Id$
 */
public class ActiveDirectoryPrincipal implements Principal, Serializable {

	private static final long serialVersionUID = 3096263076868974289L;

	private GSSName gssName;
	private Oid mech;
	private byte[] sid;
	private LdapName dn;
	private transient GSSCredential gssCredential;
	private List<String> roles;

	/**
	 * Constructs a new principal for the given parameters.
	 *
	 * @param gssName
	 *            the underlying GSS name
	 * @param mech
	 *            the underlying (negotiated) mechanism OID of the authentication
	 * @param dn
	 *            the user's distinguished name in the Active Directory forest
	 * @param roles
	 *            the roles retrieved from Active Directory
	 */
	public ActiveDirectoryPrincipal(GSSName gssName, Oid mech, byte[] sid, LdapName dn,
			GSSCredential gssCredential, List<String> roles) {
		this.gssName = gssName;
		this.mech = mech;
		this.sid = ArrayUtils.clone(sid);
		this.dn = (LdapName) dn.clone();
		this.gssCredential = gssCredential;
		this.roles = Collections.unmodifiableList(roles);
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
	 * Returns the underlying (negotiated) mechanism OID of the authentication.
	 *
	 * @return the underlying (negotiated) mechanism OID of the authentication
	 */
	public Oid getMech() {
		return mech;
	}

	/**
	 * Return the security identifier (SID) of the principal.
	 *
	 * @return the
	 */
	public byte[] getSid() {
		return ArrayUtils.clone(sid);
	}

	/**
	 * Returns the distinguished name of the principal.
	 *
	 * @return the distinguished name
	 */
	public LdapName getDn() {
		return (LdapName) dn.clone();
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

	@Override
	public int hashCode() {
		return gssName.hashCode();
	}

	@Override
	public String toString() {
		return gssName.toString();
	}

}
