package org.catcert.net;

public class HTTPSenderException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -9114658287370124859L;

	public HTTPSenderException() {
		super();
	}

	public HTTPSenderException(String message) {
		super(message);
	}

	public HTTPSenderException(String message, Throwable cause) {
		super(message, cause);
	}

	public HTTPSenderException(Throwable cause) {
		super(cause);
	}

}
