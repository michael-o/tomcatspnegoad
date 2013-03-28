package net.sf.michaelo.tomcat.authenticator;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletResponse;

import net.sf.michaelo.tomcat.realm.GssApiAwareRealm;
import net.sf.michaelo.tomcat.utils.Base64;

import org.apache.catalina.Globals;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

/**
 * A SPNEGO Authenticator which utilizes GSS-API to authenticate a client.
 * <p>
 * This authenticator has the following configuration options:
 * <ul>
 * <li>{@code loginEntryName}: Login entry name with a configured {@code Krb5LoginModule}.</li>
 * <li>{@code storeDelegatedCredential}: Store the client's/initiator's delegated credential in the
 * user principal (optional). Valid values are {@code true}, {@code false}. Default value is
 * {@code true}.</li>
 * </ul>
 * </p>
 */
/*
 * Meldungen werden im Moment nicht richtig ausgegeben wegen:
 * http://www.mail-archive.com/users@tomcat.apache.org/msg98308.html Lösung:
 * com.siemens.dynamowerk.tomcat.valve.EnhancedErrorReportValve benutzen
 */
public class SpnegoAuthenticator extends AuthenticatorBase {

	private static Log logger = LogFactory.getLog(SpnegoAuthenticator.class);

	protected static final String SPNEGO_METHOD = "SPNEGO";
	protected static final String NEGOTIATE_HEADER = "Negotiate";

	protected String loginEntryName;
	protected boolean storeDelegatedCredential = true;

	/**
	 * Sets the login entry name which establishes the GSS context.
	 * 
	 * @param loginEntryName
	 *            the login entry name
	 */
	public void setLoginEntryName(String loginEntryName) {
		this.loginEntryName = loginEntryName;
	}

	/**
	 * Sets the storage of client's/initiator's delegated credential in the user principal.
	 * 
	 * @param storeDelegatedCredential
	 *            the store delegated credential indication
	 */
	public void setStoreDelegatedCredential(boolean storeDelegatedCredential) {
		this.storeDelegatedCredential = storeDelegatedCredential;
	}

	@Override
	public String getInfo() {
		return "net.sf.michaelo.tomcat.authenticator.SpnegoAuthenticator/0.9";
	}

	protected void setUnauthorizedHeader(Response response, String message) throws IOException {
		response.setHeader("WWW-Authenticate", NEGOTIATE_HEADER);
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
	}

	protected void setException(Request request, Response response, AuthenticationException e)
			throws IOException {
		request.setAttribute(Globals.EXCEPTION_ATTR, e);
		response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
	}

	@Override
	protected boolean authenticate(Request request, Response response, LoginConfig config)
			throws IOException {

		// HttpServletRequest request = req.getRequest();
		// HttpServletResponse response = resp.getResponse();

		Principal principal = request.getUserPrincipal();
		// String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
		if (principal != null) {
			if (logger.isDebugEnabled())
				logger.debug(String.format("Already authenticated '%s'", principal));
			String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
			if (ssoId != null)
				associate(ssoId, request.getSessionInternal(true));
			return true;
		}

		// NOTE: We don't try to reauthenticate using any existing SSO session,
		// because that will only work if the original authentication was
		// BASIC or FORM, which are less secure than the DIGEST auth-type
		// specified for this webapp

		/*
		if (ssoId != null) {
			if (logger.isDebugEnabled())
				logger.debug(String.format("SSO Id %s set; attempting reauthentication", ssoId));

			if (reauthenticateFromSSO(ssoId, request))
				return true;
		}
		*/

		String authorization = request.getHeader("Authorization");

		if (!StringUtils.startsWithIgnoreCase(authorization, NEGOTIATE_HEADER)) {
			setUnauthorizedHeader(response, "Unauthorized");
			return false;
		}

		String authorizationValue = StringUtils.substringAfter(authorization, NEGOTIATE_HEADER);
		authorizationValue = StringUtils.trim(authorizationValue);

		if (StringUtils.isEmpty(authorizationValue)) {
			if (logger.isDebugEnabled())
				logger.debug("The Negotiate authorization header value sent by the client did not include a token");

			setUnauthorizedHeader(response,
					"The Negotiate authorization header value did not include a token");
			return false;
		}

		LoginContext lc = null;
		GSSContext gssContext = null;
		byte[] outToken = null;
		byte[] inToken = null;

		if (logger.isDebugEnabled())
			logger.debug("Processing Negotiate authentication token " + authorizationValue);

		try {
			inToken = Base64.decode(authorizationValue);
		} catch (Exception e) {
			logger.error("The Negotiate authorization header value sent by the client was invalid", e);

			AuthenticationException ae = new AuthenticationException(
					"The Negotiate authorization header value was invalid", e);
			setException(request, response, ae);
			return false;
		}

		try {
			try {
				lc = new LoginContext(getLoginEntryName());
				lc.login();
			} catch (LoginException e) {
				logger.error("Unable to login as the service principal", e);

				AuthenticationException ae = new AuthenticationException(
						"Unable to login as the service principal", e);
				setException(request, response, ae);
				return false;
			}

			final GSSManager manager = GSSManager.getInstance();
			final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
				@Override
				public GSSCredential run() throws GSSException {
					Oid spnegoOid = new Oid("1.3.6.1.5.5.2");
					// Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");
					return manager.createCredential(null, GSSCredential.DEFAULT_LIFETIME,
							spnegoOid, GSSCredential.ACCEPT_ONLY);
				}
			};

			gssContext = manager.createContext(Subject.doAs(lc.getSubject(), action));
			outToken = gssContext.acceptSecContext(inToken, 0, inToken.length);

			if (!gssContext.isEstablished()) {
				if (logger.isDebugEnabled())
					logger.debug("GSS context not yet established, continuing");
			} else {
				GssApiAwareRealm<?> realm = (GssApiAwareRealm<?>) context.getRealm();
				principal = realm.authenticate(gssContext, isStoreDelegatedCredential());
			}

		} catch (GSSException e) {
			logger.warn("Failed to validate client-supplied service ticket: " + authorizationValue, e);

			AuthenticationException ae = new AuthenticationException(
					"Failed to validate client-supplied service ticket", e);
			setException(request, response, ae);
			return false;
		} catch (PrivilegedActionException e) {
			logger.error("Unable to login as the service principal", e.getException());

			AuthenticationException ae = new AuthenticationException(
					"Unable to login as the service principal", e);
			setException(request, response, ae);
			return false;
		} catch (RuntimeException e) {
			// Logging erfolgt bereits im Realm
			AuthenticationException ae = new AuthenticationException(
					"Unable to perform principal search", e.getCause());
			setException(request, response, ae);
			return false;
		} finally {
			if (gssContext != null) {
				try {
					gssContext.dispose();
				} catch (GSSException e) {
					// Ignore
				}
			}
			if (lc != null) {
				try {
					lc.logout();
				} catch (LoginException e) {
					// Ignore
				}
			}
		}

		if (principal != null) {
			register(request, response, principal, SPNEGO_METHOD, principal.getName(), null);
			if (ArrayUtils.isNotEmpty(outToken)) {
				// Send response token on success only
				response.setHeader("WWW-Authenticate",
						NEGOTIATE_HEADER + " " + Base64.encode(outToken));
				// Connection must be closed due to
				// https://issues.apache.org/bugzilla/show_bug.cgi?id=54076
				response.addHeader("Connection", "close");
			}
			return true;
		}

		setUnauthorizedHeader(response, "Unauthorized");
		return false;
	}

	public String getLoginEntryName() {
		return loginEntryName;
	}

	public boolean isStoreDelegatedCredential() {
		return storeDelegatedCredential;
	}
}
