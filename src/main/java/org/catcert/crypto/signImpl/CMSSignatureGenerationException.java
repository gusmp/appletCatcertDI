package org.catcert.crypto.signImpl;

public class CMSSignatureGenerationException extends Exception {

	private static final long serialVersionUID = 7653917290494525500L;


	public CMSSignatureGenerationException() {
		super();
	}

	public CMSSignatureGenerationException(String message) {
		super(message);
	}

	public CMSSignatureGenerationException(String message, Throwable cause) {
		super(message, cause);
	}

	public CMSSignatureGenerationException(Throwable cause) {
		super(cause);
	}

}
