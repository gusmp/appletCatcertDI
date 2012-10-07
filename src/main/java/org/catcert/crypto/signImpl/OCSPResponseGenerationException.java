package org.catcert.crypto.signImpl;

public class OCSPResponseGenerationException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -845400796535676801L;

	public OCSPResponseGenerationException() {
		super();
	}

	public OCSPResponseGenerationException(String message) {
		super(message);
	}

	public OCSPResponseGenerationException(String message, Throwable cause) {
		super(message, cause);
	}

	public OCSPResponseGenerationException(Throwable cause) {
		super(cause);
	}
}
