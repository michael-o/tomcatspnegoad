package net.sf.michaelo.tomcat.realm;

import java.security.Principal;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;

/**
 * Realm definition which is able to retrieve principals from {@link GSSName GSS names} or fully
 * established {@link GSSContext GSS contexts}.
 *
 * @version $Id$
 */
public interface GSSRealm {

	/**
	 * Authenticates a user from a given GSS name.
	 *
	 * @param gssName
	 *            the GSS name of the context initiator (client)
	 * @param gssCredential
	 *            the GSS credential of the context initiator (client)
	 * @return the retrieved principal
	 * @throws NullPointerException
	 *             if the gssName is null
	 */
	// TODO Create issue for this to be added into Tomcat's Realm
	Principal authenticate(GSSName gssName, GSSCredential gssCredential);

	/**
	 * Authenticates a user from a fully established GSS context.
	 *
	 * @param gssContext
	 *            the GSS context established with the peer
	 * @param storeCred
	 *            the store delegated credential indication
	 * @return the retrieved principal
	 * @throws NullPointerException
	 *             if the gssContext is null
	 * @throws IllegalStateException
	 *             if the gssContext is not fully established
	 */
	// TODO Remove this method in the next iteration. It is already in RealmBase
	Principal authenticate(GSSContext gssContext, boolean storeCred);

}
