package org.catcert.crypto.keyStoreImpl;

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
public class MSKeyStore {

	public static final String USER_STORE = "Windows-MY";
	public static final String MACHINE_STORE = "Windows-ROOT";
	public static final String CAPI = "CryptoAPI";

	/**
	 * 
	 * @param store
	 * @return
	 * @throws MSKeyStoreException
	 */
	public static KeyStore loadWindowsKeyStore(String store) throws MSKeyStoreException {		
		try {			
			KeyStore keyStore = KeyStore.getInstance(store);
			keyStore.load(null, null);

			return keyStore;

		} catch (SecurityException e) {
			e.printStackTrace();
			throw new MSKeyStoreException(e.getMessage());
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			throw new MSKeyStoreException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new MSKeyStoreException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new MSKeyStoreException(e.getMessage());
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new MSKeyStoreException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new MSKeyStoreException(e.getMessage());
		} catch (Throwable e) {
			e.printStackTrace();
			throw new MSKeyStoreException("Error carregant dll per accedir al magatzem de Microsoft");			
		}
	}
}
