package org.catcert.crypto.keyStoreImpl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

/**
 * 
 * @author oburgos
 *
 */
public class PKCS11KeyStore{

	private static final String PKCS11_KEYSTORE_TYPE = "PKCS11";

	private static final String SUN_PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";

	/** 
	 * Loads the keystore from the smart card using its PKCS#11 implementation
	 * library and the Sun PKCS#11 security provider. The PIN code for accessing
	 * the smart card is required.
	 *
	 * @param PKCS11LibraryFileName
	 * @param PIN
	 * @return
	 * @throws PKCS11KeyStoreException
	 */
	public static KeyStore loadKeyStoreFromSmartCard(String PKCS11LibraryFileName, char[] PIN) throws PKCS11KeyStoreException {		
		try {
			// First configure the Sun PKCS#11 provider. It requires a stream (or file)
			// containing the configuration parameters - "name" and "library".
			String pkcs11ConfigSettings = "name = SmartCard\n" + "library = " + PKCS11LibraryFileName;
			byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
			ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);
			
			// Instantiate the provider dynamically with Java reflection		
			Class sunPkcs11Class = Class.forName(SUN_PKCS11_PROVIDER_CLASS);
			Constructor pkcs11Constr = sunPkcs11Class.getConstructor(InputStream.class);
			Provider pkcs11Provider = (Provider) pkcs11Constr.newInstance(confStream);
			Security.addProvider(pkcs11Provider);
			
			// Read the keystore form the smart card
			KeyStore keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE);
			keyStore.load(null, PIN);

			return keyStore;
			
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (SecurityException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (NoSuchMethodException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (InstantiationException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (IllegalAccessException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (InvocationTargetException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new PKCS11KeyStoreException(e.getMessage());
		}		
	}
}
