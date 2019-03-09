/*
 * Copyright 2013–2019 Michael Osipov
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

import org.apache.catalina.Realm;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;

/**
 * Realm interface which is able to retrieve principals from {@link GSSName GSS names} or fully
 * established {@link GSSContext GSS contexts}.
 *
 * @version $Id$
 */
public interface GSSRealm extends Realm {

	/**
	 * Authenticates a user from a given GSS name.
	 *
	 * @param gssName
	 *            the GSS name of the context initiator (client)
	 * @param gssCredential
	 *            the GSS credential of the context initiator (client)
	 * @return the retrieved principal
	 */
	// TODO Create issue for this to be added into Tomcat's Realm
	Principal authenticate(GSSName gssName, GSSCredential gssCredential);

	/**
	 * Authenticates a user from a fully established GSS context.
	 *
	 * @param gssContext
	 *            the GSS context established with the peer
	 * @param storeCreds
	 *            the store delegated credential indication
	 * @return the retrieved principal
	 */
	// TODO Remove this method in the next iteration. It is already in RealmBase
	Principal authenticate(GSSContext gssContext, boolean storeCreds);

}
