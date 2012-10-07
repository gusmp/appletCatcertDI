package org.catcert.psis;


public class PSISValidationException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5391513744668590808L;

	public PSISValidationException() {
		super();
	}

	public PSISValidationException(String message) {
		super(message);
	}

	public PSISValidationException(String message, Throwable cause) {
		super(message, cause);
	}

	public PSISValidationException(Throwable cause) {
		super(cause);
	}
}
