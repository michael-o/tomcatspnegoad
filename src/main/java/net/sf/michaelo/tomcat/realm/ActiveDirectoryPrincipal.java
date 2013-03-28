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
 */
public class ActiveDirectoryPrincipal implements Principal, Serializable {

	private static final long serialVersionUID = 3096263076868974289L;

	private KerberosPrincipal principal;
	private String dn;
	private byte[] sid;
	private transient GSSCredential gssCredential;
	private List<String> roles;

	/**
	 * Constructs a new principal.
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

	public String getDn() {
		return dn;
	}

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

	public GSSCredential getDelegatedCredential() {
		return gssCredential;
	}

}
