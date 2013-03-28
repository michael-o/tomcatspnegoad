package net.sf.michaelo.tomcat.authenticator;

public class AuthenticationException extends Exception {

	private static final long serialVersionUID = 1933003623124900749L;

	public AuthenticationException(String message, Throwable cause) {
		super(message, cause);
	}

}
