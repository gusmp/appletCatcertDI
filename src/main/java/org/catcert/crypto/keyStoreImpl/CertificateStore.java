package org.catcert.crypto.keyStoreImpl;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Vector;

import org.catcert.AddCAPIProvider;
import org.catcert.crypto.utils.Utils;

/**
 * 
 * @author oburgos
 * @author aciffone
 *
 */
public class CertificateStore {

	public static final int Generic_keystore = 0;
	public static final int MS_keystore = 1;
	public static final int PKCS12_keystore = 2;
	public static final int Smartcard_keystore = 3;
	public static final int Mozilla_keystore = 4;
	public static final int Java_keystore = 5;
	public static final int MacOSX_keystore = 6;

	private KeyStore store;
	private HashMap<String,String> aliases = new HashMap<String,String>();

	/**
	 * 
	 * @param keystoreType
	 * @param argInput
	 * @param PIN
	 * @throws CertificateStoreException
	 */
	public CertificateStore(int keystoreType, String argInput, char[] PIN) throws CertificateStoreException {
		switch (keystoreType) {
		case MS_keystore:
			try {
				try {
					AddCAPIProvider.load();
				} catch (FileNotFoundException e) {
					e.printStackTrace();
					throw new CertificateStoreException(e.getMessage(),e.getCause());
				} catch (IOException e) {
					e.printStackTrace();
					throw new CertificateStoreException(e.getMessage(),e.getCause());
				}
				store = MSKeyStore.loadWindowsKeyStore(MSKeyStore.CAPI);
			} catch (MSKeyStoreException e) {
				e.printStackTrace();
				throw new CertificateStoreException(e.getMessage(),e.getCause());
			}
			break;
		case PKCS12_keystore:
			try {
				store = PKCS12KeyStore.loadKeyStoreFromPFXFile(argInput, PIN);
			} catch (PKCS12KeyStoreException e) {
				e.printStackTrace();
				throw new CertificateStoreException(e.getMessage());
			}
			break;
		case Smartcard_keystore:
			try {
				store = PKCS11KeyStore.loadKeyStoreFromSmartCard(argInput, PIN);
			} catch (PKCS11KeyStoreException e) {
				e.printStackTrace();
				throw new CertificateStoreException(e.getMessage());
			}
			break;
		case Mozilla_keystore:
			try {
				store = MozillaKeyStore.loadNSSkeystore();
			} catch (MozillaKeyStoreException e) {
				e.printStackTrace();
				throw new CertificateStoreException(e.getMessage());
			}
			break;
		case Java_keystore:
			try {
				store = JavaKeyStore.loadJavaKeyStoreFromFile(argInput, PIN);
			} catch (JavaKeyStoreException e) {
				e.printStackTrace();
				throw new CertificateStoreException(e.getMessage(),e.getCause());
			}		
			break;
		case MacOSX_keystore:
			try {
				store = MacOSXKeyStore.loadMacOSXKeystore(MacOSXKeyStore.KEY_CHAIN_STORE);
			} catch (MacOSXKeyStoreException e) {
				e.printStackTrace();
				throw new CertificateStoreException(e.getMessage());
			}
			break;
		default:
			throw new CertificateStoreException("keystore specified doesn't exists, keyStore_type: " + keystoreType);
		}
	}

	/**
	 * 
	 * @return
	 */
	public KeyStore getStore() {
		return store;
	}

	/**
	 * 
	 * @param allowed_CAs
	 * @param CN
	 * @return
	 * @throws CertificateStoreException
	 */
	public Object[] getSigningCertificates(Vector<String> allowed_CAs, Vector<String> allowed_OIDs, String subject_Text) throws CertificateStoreException {
		try {
			Enumeration<String> certs = store.aliases();
			while (certs.hasMoreElements()) {
				String current_alias = certs.nextElement();
				X509Certificate cert = (X509Certificate) store.getCertificate(current_alias);
				if(cert.getKeyUsage() != null)
					if (cert.getKeyUsage()[0] == true || cert.getKeyUsage()[1] == true)
						if(checkValidityPeriod(cert))
							if(isCAallowed(cert, allowed_CAs))
								if(isOIDallowed(cert, allowed_OIDs))
									if(isTextinSubjectDN(cert, subject_Text)){
										try {
											// tractament especial per a keystores MAC OS X
											if(store.getProvider().getName().equals("Apple")){
												if(store.getKey(current_alias,"nonnull".toCharArray()) != null)
													aliases.put(Utils.getCN(cert, "subject") + " (" + Utils.getCN(cert, "issuer") + ") - SN: " + cert.getSerialNumber(), current_alias);		
											}else{
												aliases.put(Utils.getCN(cert, "subject") + " (" + Utils.getCN(cert, "issuer") + ") - SN: " + cert.getSerialNumber(), current_alias);		
											}
										} catch (NoSuchAlgorithmException e) {
											e.printStackTrace();
										} catch (UnrecoverableKeyException e) {
											e.printStackTrace();
										}								
									}
																			
			}

			if (aliases.isEmpty())
				throw new KeyStoreException("No hi ha certificats disponibles per a signar");

			return aliases.keySet().toArray();

		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new CertificateStoreException(e.getMessage());
		}		
	}

	/**
	 * 
	 * @param allowed_CAs
	 * @param CN
	 * @return
	 * @throws CertificateStoreException
	 */
	public Object[] getCipherCertificates(Vector<String> allowed_CAs, Vector<String> allowed_OIDs, String subject_Text) throws CertificateStoreException {		
		try {
			Enumeration<String> certs = store.aliases();
			while (certs.hasMoreElements()) {
				String current_alias = certs.nextElement();
				X509Certificate cert = (X509Certificate) store.getCertificate(current_alias); 
				if(cert.getKeyUsage() != null)
					if (cert.getKeyUsage()[3] == true)
						if(checkValidityPeriod(cert))
							if(isCAallowed(cert, allowed_CAs))
								if(isOIDallowed(cert, allowed_OIDs))
									if(isTextinSubjectDN(cert, subject_Text))
										aliases.put(Utils.getCN(cert, "subject") + " (" + Utils.getCN(cert, "issuer") + ")", current_alias);
			}

			if (aliases.isEmpty())
				throw new KeyStoreException("No hi ha certificats disponibles per a xifrar");

			return aliases.keySet().toArray();

		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new CertificateStoreException(e.getMessage());
		}	
	}

	/**
	 * 
	 * @param CN
	 * @return
	 */
	public String getAliasFromCN(String CN) {
		return aliases.get(CN);
	}

	/**
	 * 
	 * @param alias
	 * @return
	 * @throws KeyStoreException
	 */
	public Object[] getCNFromAlias(String alias) throws KeyStoreException {
		if(store.containsAlias(alias)) {			
			X509Certificate cert = (X509Certificate) store.getCertificate(alias);
			aliases.put(Utils.getCN(cert, "subject") + " (" + Utils.getCN(cert, "issuer") + ")", alias);
			return new Object[] {Utils.getCN(cert, "subject")};
		}
		else
			throw new KeyStoreException("No hi ha certificats disponibles per a signar");
	}

	/**
	 * 
	 * @param alias
	 * @return
	 * @throws KeyStoreException
	 */
	public boolean isSelectedAliasInKeystore(String alias) throws KeyStoreException {
		return store.containsAlias(alias);
	}

	/**
	 * 
	 * @param cert
	 * @return
	 */
	private boolean checkValidityPeriod(X509Certificate cert) {
		//Controla la caducitat del certificat en la data sol·licitada.
		try {
			GregorianCalendar calendar = new GregorianCalendar();
			cert.checkValidity(calendar.getTime());
			return true;
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
			return false;
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
			return false;
		}
	}

	/**
	 * 
	 * @param cert
	 * @param allowed_CAs
	 * @return
	 */
	private boolean isCAallowed(X509Certificate cert, Vector<String> allowed_CAs) {
		if(allowed_CAs == null)
			return true;

		String issuerCN = Utils.getCN(cert, "issuer");
		if(issuerCN == null)
			return false;

		for (int i=0; i<allowed_CAs.size(); i++)
			if(issuerCN.equalsIgnoreCase(allowed_CAs.get(i)))
				return true;

		return false;
	}

	private boolean isOIDallowed(X509Certificate cert, Vector<String> allowed_OIDs) {
		if(allowed_OIDs == null)
			return true;
		
		String[] certPolicy;
		try {
			certPolicy = Utils.getCertificatePolicyOIDs(cert);
		} catch (CertificateException e) {
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		if(certPolicy!=null){
			for (int i=0; i<allowed_OIDs.size(); i++){
				for(int j=0; j<certPolicy.length; j++){
					if(certPolicy[j].equals(allowed_OIDs.get(i))){
						return true;
					}
				}
			}
			return false;
		}else{
			return false;
		}
	}

	/**
	 * 
	 * @param cert
	 * @param subject_Text
	 * @return
	 */
	private boolean isTextinSubjectDN(X509Certificate cert, String subject_Text) {
		if(subject_Text == null)
			return true;

		String DN = cert.getSubjectX500Principal().getName("RFC1779").toLowerCase();
		if(DN.indexOf(subject_Text.toLowerCase()) > 0)
			return true;
		else
			return false;
	}
}