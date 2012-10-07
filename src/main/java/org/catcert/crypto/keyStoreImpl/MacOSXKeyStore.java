package org.catcert.crypto.keyStoreImpl;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
//import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
//import java.util.Enumeration;

/**
 * 
 * @author oburgos
 * @author ciffone
 *
 */
public class MacOSXKeyStore {
	
	public static final String KEY_CHAIN_STORE = "KeychainStore";
	
	/**
	 * 
	 * @param type
	 * @return
	 * @throws MacOSXKeyStoreException
	 */
	public static KeyStore loadMacOSXKeystore(String type) throws MacOSXKeyStoreException {		
		try {			
			KeyStore keyStore = KeyStore.getInstance(type, "Apple");		
//			keyStore.load(new FileInputStream("/USER_HOME/Library/Keychains/login.keychain"),null);
			keyStore.load(null, null);
			
			// TEST PURPOUSE ONLY ******************
//			for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements() ;) {
//				String alias = aliases.nextElement();
//				System.out.println("ALIAS : " + alias);
//				
//				if(keyStore.getCertificate(alias) != null)
//					System.out.println(" TÉ CERTIFICAT ");
//				else
//					System.out.println(" NO TÉ CERTIFICAT ");
//				
//				try {
//					if(keyStore.getKey(alias, "-".toCharArray()) != null)
//						System.out.println(" TÉ CLAU PRIVADA!!!! ");
//					else
//						System.out.println(" NO TÉ CLAU PRIVADA ");
//				} catch (UnrecoverableKeyException e) {
//					System.out.println(" ERROR COMPROVANT SI DISPOSA DE LA MALEIDA CLAU PRIVADA ");
//				}
//				
//		     }
			// ****************** TEST PURPOUSE ONLY
	        
	        return keyStore;
	        
		} catch (SecurityException e) {
			e.printStackTrace();
			throw new MacOSXKeyStoreException(e.getMessage());
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			throw new MacOSXKeyStoreException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new MacOSXKeyStoreException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new MacOSXKeyStoreException(e.getMessage());
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new MacOSXKeyStoreException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new MacOSXKeyStoreException(e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new MacOSXKeyStoreException(e.getMessage());
		}		
	}
}
