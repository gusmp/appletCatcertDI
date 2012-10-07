package org.catcert.crypto.keyStoreImpl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * 
 * @author aciffone
 *
 */
public class JavaKeyStore {

	private static final String JAVA_KEYSTORE_TYPE = "JKS";

	public static KeyStore loadJavaKeyStoreFromFile(String fileName, char[] PIN) throws JavaKeyStoreException {		

		try{
			
			KeyStore keyStore = KeyStore.getInstance(JAVA_KEYSTORE_TYPE);
			FileInputStream keyStoreStream = new FileInputStream(fileName);
			keyStore.load(keyStoreStream, PIN);
			return keyStore;
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new JavaKeyStoreException(e.getMessage(), e.getCause());
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new JavaKeyStoreException(e.getMessage(), e.getCause());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new JavaKeyStoreException(e.getMessage(), e.getCause());
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new JavaKeyStoreException(e.getMessage(), e.getCause());
		} catch (IOException e) {
			e.printStackTrace();
			throw new JavaKeyStoreException(e.getMessage(), e.getCause());
		}
	}
}
