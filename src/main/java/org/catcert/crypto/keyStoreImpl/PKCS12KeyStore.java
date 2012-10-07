package org.catcert.crypto.keyStoreImpl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * 
 * @author oburgos
 *
 */
public class PKCS12KeyStore {
	
	private static final String PKCS12_KEYSTORE_TYPE = "PKCS12";
	
	/**
	 * 
	 * @param fileName
	 * @param PIN
	 * @return
	 * @throws PKCS12KeyStoreException
	 */
	public static KeyStore loadKeyStoreFromPFXFile(String fileName, char[] PIN) throws PKCS12KeyStoreException {		
		try {			
			KeyStore keyStore = KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
			FileInputStream keyStoreStream = new FileInputStream(fileName);
	        keyStore.load(keyStoreStream, PIN);
	        
	        return keyStore;
	        
		} catch (SecurityException e) {
			e.printStackTrace();
			throw new PKCS12KeyStoreException(e.getMessage());
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			throw new PKCS12KeyStoreException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new PKCS12KeyStoreException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new PKCS12KeyStoreException(e.getMessage());
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new PKCS12KeyStoreException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new PKCS12KeyStoreException(e.getMessage());
		}
	}
}
