package org.catcert.crypto.signImpl;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import lib.org.bouncycastle.asn1.ASN1EncodableVector;
import lib.org.bouncycastle.asn1.ASN1OctetString;
import lib.org.bouncycastle.asn1.ASN1Sequence;
import lib.org.bouncycastle.asn1.DEREncodableVector;
import lib.org.bouncycastle.asn1.DERObject;
import lib.org.bouncycastle.asn1.DERObjectIdentifier;
import lib.org.bouncycastle.asn1.DEROctetString;
import lib.org.bouncycastle.asn1.DERSequence;
import lib.org.bouncycastle.asn1.DERSequenceGenerator;
import lib.org.bouncycastle.asn1.DERSet;
import lib.org.bouncycastle.asn1.DERTaggedObject;
import lib.org.bouncycastle.asn1.DERUTCTime;
import lib.org.bouncycastle.asn1.cms.Attribute;
import lib.org.bouncycastle.asn1.cms.AttributeTable;
import lib.org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import lib.org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import lib.org.bouncycastle.asn1.esf.SignaturePolicyId;
import lib.org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import lib.org.bouncycastle.asn1.esf.SignerAttribute;
import lib.org.bouncycastle.asn1.ess.ESSCertID;
import lib.org.bouncycastle.asn1.ess.SigningCertificate;
import lib.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import lib.org.bouncycastle.cms.CMSException;
import lib.org.bouncycastle.cms.CMSProcessable;
import lib.org.bouncycastle.cms.CMSProcessableByteArray;
import lib.org.bouncycastle.cms.CMSSignedData;
import lib.org.bouncycastle.cms.CMSSignedDataGenerator;
import lib.org.bouncycastle.util.encoders.Base64;

import org.catcert.crypto.utils.Utils;
import org.catcert.psis.PSISValidation;
import org.catcert.psis.PSISValidationException;

/**
 * 
 * @author oburgos
 * @author ciffone
 *
 */
public class CMSSignatureGeneration {

	// CAdES level
	public static final int CMS = 1;
	public static final int CAdES_BES = 2;
	public static final int CAdES_T = 3;
	public static final int CAdES_C = 4;

	// Hash algorithm OID's
	private static final String SHA1OID = "1.3.14.3.2.26";
	private static final String SHA256OID = "2.16.840.1.101.3.4.2.1";
	private static final String SHA512OID = "2.16.840.1.101.3.4.2.3";

	// Hash algorithm Id's
	private static final String SHA1 = "SHA-1";
	private static final String SHA256 = "SHA-256";
	private static final String SHA512 = "SHA-512";


	/**
	 * Signa un document a partir del keystore indicat, de l'alias del certificat amb el que es vol signar, 
	 * i del pin de la tarjeta criptogràfica. Retorna la signatura en format base64.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param browserCookie
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signToBase64(File docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String browserCookie) throws CMSSignatureGenerationException{
		return signToBase64(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, TsaUrl.PSIS_TSA_URL, browserCookie);
	}


	/**
	 * Signa un document a partir del keystore indicat, de l'alias del certificat amb el que es vol signar, 
	 * i del pin de la tarjeta criptogràfica. Retorna la signatura en format base64.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @param browserCookie
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signToBase64(File docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url, String browserCookie) throws CMSSignatureGenerationException{
		byte[] signature = sign(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID, policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, tsa_url);
		if (signature != null)
			return Base64.encode(signature);
		else
			return null;
	}


	/**
	 * Signa un document a partir del keystore indicat, de l'alias del certificat amb el que es vol signar, 
	 * i del pin de la tarjeta criptogràfica. Retorna la signatura en format base64.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signToBase64(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings) throws CMSSignatureGenerationException{
		return (signToBase64(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, TsaUrl.PSIS_TSA_URL));
	}


	/**
	 * Signa un document a partir del keystore indicat, de l'alias del certificat amb el que es vol signar, 
	 * i del pin de la tarjeta criptogràfica. Retorna la signatura en format base64.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signToBase64(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url) throws CMSSignatureGenerationException{
		return signToBase64(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, tsa_url, false, null);
	}	

	/**
	 * Signa un document a partir del keystore indicat, de l'alias del certificat amb el que es vol signar, 
	 * i del pin de la tarjeta criptogràfica. Retorna la signatura en format base64.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signToBase64(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url, boolean psisValidation, String requiredNif) throws CMSSignatureGenerationException{
		byte[] signature = sign(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID, policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, tsa_url, psisValidation, requiredNif);
		if (signature != null)
			return Base64.encode(signature);
		else
			return null;
	}

	/**
	 * Signa un document a partir del keystore indicat, de l'alias del certificat amb el que es vol signar, 
	 * i del pin de la tarjeta criptogràfica.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] sign(File docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings) throws CMSSignatureGenerationException{
		return sign(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, TsaUrl.PSIS_TSA_URL);
	}

	/**
	 * Signa un document a partir del keystore indicat, de l'alias del certificat amb el que es vol signar, 
	 * i del pin de la tarjeta criptogràfica.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] sign(File docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url) throws CMSSignatureGenerationException{
		try {
			return sign(Utils.streamToByteArray(new FileInputStream(docToSign)), keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID, policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, tsa_url);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new CMSSignatureGenerationException(e.getMessage());
		} catch (CMSSignatureGenerationException e) {
			e.printStackTrace();
			throw new CMSSignatureGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new CMSSignatureGenerationException(e.getMessage());
		}		 
	}


	/**
	 * METODE PER SIGNAR EN MODE SERVIDOR, NO S'HA DE MODIFICAR LA SIGNATURA D'AQUEST MÈTODE
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, HashMap<String, String> proxySettings) throws CMSSignatureGenerationException{
		return sign(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, null, null, proxySettings, TsaUrl.PSIS_TSA_URL);
	}

	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param signerRole
	 * @param commitment_identifiers
	 * @param commitmentTypeIdentifier
	 * @param proxySettings
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, List<String> commitmentTypeIdentifier, HashMap<String, String> proxySettings) throws CMSSignatureGenerationException{
		return sign(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, TsaUrl.PSIS_TSA_URL);
	}

	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url) throws CMSSignatureGenerationException{
		return sign(docToSign, keyStore, alias, pin, attached, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, tsa_url, false, null);
	}



	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param attached
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, boolean attached, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url, boolean psisValidation, String requiredNif) throws CMSSignatureGenerationException{
		try{			
			//certificat
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);

			//validació del certificat contra PSIS
			if(psisValidation){
				PSISValidation validator = new PSISValidation(requiredNif, proxySettings);
				boolean validCert = validator.Validate(cert.getEncoded());
				if(!validCert){
					throw new PSISValidationException(validator.getError());
				}
			}

			//clau privada
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pin);			

			//Recuperem la cadena de certificats
			Certificate[] certificationChain = keyStore.getCertificateChain(alias);
			if (certificationChain == null)
				certificationChain = new Certificate[] {cert};
			CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(certificationChain)), "BC");

			//signem el document

			//generador de signatura CMS
			CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();			
			CMSProcessable content = new CMSProcessableByteArray(docToSign);

			if(signedAttributes == null)
				signedAttributes = new AttributeTable(new DEREncodableVector());

			//generem la signatura tenint en compte el tipus de KeyStore i el nivell de signatura avançada.
			switch(CAdESLevel) {
			//case CMS: default signed_attributes, excepte en el cas de PDF, però ja venen generats.
			case CAdES_BES:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				break;
			case CAdES_T:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				break;
			case CAdES_C:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				break;
			}

			// afegim els atributs de la EPES
			if(policyID != null && policyHash != null && CAdESLevel > CMS) {
				addEPESAttributes(signedAttributes, policyID, policyHash, policyHash_algIdentifierID, signerRole,commitment_identifiers);
			}

			signGen.addSigner(privateKey, cert, AlgorithmIDtoOID(hash_algorithmID), signedAttributes, null);
			signGen.addCertificatesAndCRLs(certStore);

			CMSSignedData signedData = signGen.generate(CMSSignedDataGenerator.DATA, content, attached, keyStore.getProvider().getName().equals("Apple") ? "BC" : keyStore.getProvider().getName(), true);

			// Si es sol·licita el TimeStamp, l'afegim com a atribut no signat
			if(TimeStamped || CAdESLevel >= CAdES_T)
				signedData = TimeStampGeneration.addTimeStampToSignature(signedData, proxySettings, tsa_url);			

			//retornem el byte[] de la signatura generada
			return signedData.getEncoded();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			String errMsg = "Problemes en obrir el document a signar:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (IOException e) {
			e.printStackTrace();
			String errMsg = "Problemes en obrir el document a signar:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			String errMsg = "Problemes en l'accés al magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			String errMsg = "No ha estat possible recuperar la clau privada del magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			String errMsg = "No ha estat possible recuperar la clau privada del magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			String errMsg = "Problemes en crear el magatzem de certificats. No s'ha trobat el proveïdor.\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (CMSException e) {
			e.printStackTrace();
			return null;
		} catch (TimeStampGenerationException e) {
			e.printStackTrace();
			String errMsg = "Problemes durant la generació del segell de temps:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (Throwable e) {
			e.printStackTrace();
			String errMsg = "Problemes durant la generació de la signatura: error desconegut.\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		}
	}

	/**
	 * 
	 * @param documentHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signHashToBase64(byte[] documentHash, KeyStore keyStore, String alias, char[] pin, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings) throws CMSSignatureGenerationException{
		return signHashToBase64(documentHash, keyStore, alias, pin, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, TsaUrl.PSIS_TSA_URL);
	}


	/**
	 * 
	 * @param documentHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signHashToBase64(byte[] documentHash, KeyStore keyStore, String alias, char[] pin, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url) throws CMSSignatureGenerationException{
		return signHashToBase64(documentHash, keyStore, alias, pin, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID, policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, tsa_url, false, null);
	}
	/**
	 * 
	 * @param documentHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signHashToBase64(byte[] documentHash, KeyStore keyStore, String alias, char[] pin, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url, boolean psisValidation, String requiredNif) throws CMSSignatureGenerationException{
		byte[] signature = signHash(documentHash, keyStore, alias, pin, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID, policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, tsa_url, psisValidation, requiredNif);
		if (signature != null)
			return Base64.encode(signature);
		else
			return null;
	}

	/**
	 * 
	 * @param documentHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signHash(byte[] documentHash, KeyStore keyStore, String alias, char[] pin, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings) throws CMSSignatureGenerationException{
		return signHash(documentHash, keyStore, alias, pin, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID,
				policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, TsaUrl.PSIS_TSA_URL); 
	}


	/**
	 * 
	 * @param documentHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signHash(byte[] documentHash, KeyStore keyStore, String alias, char[] pin, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url) throws CMSSignatureGenerationException{
		return signHash(documentHash, keyStore, alias, pin, TimeStamped, CAdESLevel, signedAttributes, hash_algorithmID, policyID, policyHash, policyHash_algIdentifierID, signerRole, commitment_identifiers, proxySettings, tsa_url, false, null);
	}	
	/**
	 * 
	 * @param documentHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signHash(byte[] documentHash, KeyStore keyStore, String alias, char[] pin, boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url, boolean psisValidation, String requiredNif) throws CMSSignatureGenerationException{
		try{			
			//certificat
			//HSM: esto fallara con el HSM
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);

			//validació del certificat contra PSIS
			if(psisValidation){
				PSISValidation validator = new PSISValidation(requiredNif, proxySettings);
				boolean validCert = validator.Validate(cert.getEncoded());
				if(!validCert)
					throw new PSISValidationException(validator.getError());
			}

			//clau privada
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pin);			

			//Recuperem la cadena de certificats
			Certificate[] certificationChain = keyStore.getCertificateChain(alias);
			if (certificationChain == null)
				certificationChain = new Certificate[] {cert};
			CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(certificationChain)), "BC");

			//signem el document

			//generador de signatura CMS
			CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();
			CMSProcessable content = new CMSProcessableByteArray(documentHash);

			// default attributes
			if(signedAttributes == null)
				signedAttributes = CMSSignatureGeneration.buildAuthenticatedAttributes(documentHash, cert, false, proxySettings);

			//generem la signatura tenint en compte el tipus de KeyStore i el nivell de signatura avançada.
			switch(CAdESLevel) {
			//case CMS: default signed_attributes, excepte en el cas de PDF, però ja venen generats.
			case CAdES_BES:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				break;
			case CAdES_T:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				TimeStamped = true;
				break;
			case CAdES_C:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				break;
			}

			if(policyID != null && policyHash != null && CAdESLevel > CMS) {
				addEPESAttributes(signedAttributes, policyID, policyHash, policyHash_algIdentifierID,signerRole,commitment_identifiers);
			}

			signGen.addSigner(privateKey, cert, AlgorithmIDtoOID(hash_algorithmID), signedAttributes, null);
			signGen.addCertificatesAndCRLs(certStore);

			//HSM: mirar el provider!!! String provider = "nCipherKM";
			CMSSignedData signedData = signGen.generate(CMSSignedDataGenerator.DATA, content, false, keyStore.getProvider().getName().equals("Apple") ? "BC" : keyStore.getProvider().getName());

			// Si es sol·licita el TimeStamp, l'afegim com a atribut no signat
			if(TimeStamped || CAdESLevel >= CAdES_T)
				signedData = TimeStampGeneration.addTimeStampToSignature(signedData, proxySettings, tsa_url);

			//retornem el byte[] de la signatura generada
			return signedData.getEncoded();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			String errMsg = "Problemes en obrir el document a signar:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (IOException e) {
			e.printStackTrace();
			String errMsg = "Problemes en obrir el document a signar:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			String errMsg = "Problemes en l'accés al magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			String errMsg = "No ha estat possible recuperar la clau privada del magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			String errMsg = "No ha estat possible recuperar la clau privada del magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			String errMsg = "Problemes en crear el magatzem de certificats. No s'ha trobat el proveïdor.\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (CMSException e) {
			e.printStackTrace();
			return null;
		} catch (TimeStampGenerationException e) {
			e.printStackTrace();
			String errMsg = "Problemes durant la generació del segell de temps:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (Throwable e) {
			e.printStackTrace();
			String errMsg = "Problemes durant la generació de la signatura: error desconegut.\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		}
	}
	
	/**
	 * 
	 * @param documentHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param TimeStamped
	 * @param CAdESLevel
	 * @param signedAttributes
	 * @param hash_algorithmID
	 * @param policyID
	 * @param policyHash
	 * @param policyHash_algIdentifierID
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static byte[] signHashHSM(byte[] documentHash, KeyStore keyStore, String alias, char[] pin, 
			boolean TimeStamped, int CAdESLevel, AttributeTable signedAttributes, String hash_algorithmID,
			String policyID, String policyHash, String policyHash_algIdentifierID, String signerRole, 
			List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url, 
			boolean psisValidation, String requiredNif,X509Certificate certificate) throws CMSSignatureGenerationException
	{
		try{			
			//certificat que realitza la signatura
			//HSM: aixó fallará amb el HSM ja que no té el certificat
			//X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
			X509Certificate cert = certificate;
			//Fi HSM

			//validació del certificat contra PSIS
			if(psisValidation){
				PSISValidation validator = new PSISValidation(requiredNif, proxySettings);
				boolean validCert = validator.Validate(cert.getEncoded());
				if(!validCert)
					throw new PSISValidationException(validator.getError());
			}

			//clau privada
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pin);			

			//Recuperem la cadena de certificats
			Certificate[] certificationChain = keyStore.getCertificateChain(alias);
			if (certificationChain == null)
				certificationChain = new Certificate[] {cert};
			CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(certificationChain)), "BC");

			//signem el document

			//generador de signatura CMS
			CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();
			CMSProcessable content = new CMSProcessableByteArray(documentHash);

			// default attributes
			if(signedAttributes == null)
				signedAttributes = CMSSignatureGeneration.buildAuthenticatedAttributes(documentHash, cert, false, proxySettings);

			//generem la signatura tenint en compte el tipus de KeyStore i el nivell de signatura avançada.
			switch(CAdESLevel) {
			//case CMS: default signed_attributes, excepte en el cas de PDF, però ja venen generats.
			case CAdES_BES:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				break;
			case CAdES_T:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				TimeStamped = true;
				break;
			case CAdES_C:
				signedAttributes = addCAdESAttributes(signedAttributes, cert, hash_algorithmID);
				break;
			}

			if(policyID != null && policyHash != null && CAdESLevel > CMS) {
				addEPESAttributes(signedAttributes, policyID, policyHash, policyHash_algIdentifierID,signerRole,commitment_identifiers);
			}

			signGen.addSigner(privateKey, cert, AlgorithmIDtoOID(hash_algorithmID), signedAttributes, null);
			signGen.addCertificatesAndCRLs(certStore);

			//HSM: el provider ha de ser el HSM
			CMSSignedData signedData = signGen.generate(CMSSignedDataGenerator.DATA, content, false, keyStore.getProvider().getName().equals("Apple") ? "BC" : keyStore.getProvider().getName());
			//Fi HSM
			
			// Si es sol·licita el TimeStamp, l'afegim com a atribut no signat
			if(TimeStamped || CAdESLevel >= CAdES_T)
				signedData = TimeStampGeneration.addTimeStampToSignature(signedData, proxySettings, tsa_url);

			//retornem el byte[] de la signatura generada
			return signedData.getEncoded();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			String errMsg = "Problemes en obrir el document a signar:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (IOException e) {
			e.printStackTrace();
			String errMsg = "Problemes en obrir el document a signar:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			String errMsg = "Problemes en l'accés al magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			String errMsg = "No ha estat possible recuperar la clau privada del magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			String errMsg = "No ha estat possible recuperar la clau privada del magatzem de claus:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			String errMsg = "Problemes en crear el magatzem de certificats. No s'ha trobat el proveïdor.\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		} catch (CMSException e) {
			e.printStackTrace();
			return null;
		} catch (TimeStampGenerationException e) {
			e.printStackTrace();
			String errMsg = "Problemes durant la generació del segell de temps:\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);
		} catch (Throwable e) {
			e.printStackTrace();
			String errMsg = "Problemes durant la generació de la signatura: error desconegut.\n" + e.getMessage();
			throw new CMSSignatureGenerationException(errMsg);			
		}
	}
	
	

	/**
	 * 
	 * @param hash
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static AttributeTable buildAuthenticatedAttributes(byte[] hash, X509Certificate cert, boolean pdf, HashMap<String, String> proxySettings) {
		DERSet ds;
		DEREncodableVector dv = new DEREncodableVector();

		// PDF Revocation Info
		if(pdf) {
			try {
				// Create OCSP Request
				//OCSPResp ocspResp = OCSPResponseGeneration.generateOCSPResponse(Utils.getCN(cert, "issuer"), cert.getSerialNumber(), proxySettings);

				//X509Certificate OCSPResponder = ((BasicOCSPResp) ocspResp.getResponseObject()).getCerts("BC")[0];
				//DERObject crlResponse = CRLResponseGeneration.generateCRLResponse(OCSPResponder, proxySettings);

				// Per borrar si es descomenta l'OCSP
				DERObject crlResponse = CRLResponseGeneration.generateCRLResponse(cert, proxySettings);	


				//ASN1InputStream asn1InputStream = new ASN1InputStream(ocspResp.getEncoded());
				//DERObject ocspDER = asn1InputStream.readObject();
				DEREncodableVector crlsAndOCSPseq = new DEREncodableVector();
				crlsAndOCSPseq.add(new DERTaggedObject(true, 0, new DERSequence(crlResponse))); //CRL on comprovar OCSP responder
				//crlsAndOCSPseq.add(new DERTaggedObject(true, 1, new DERSequence(ocspDER))); //OCSP response
				ds = new DERSet(new DERSequence(crlsAndOCSPseq));
				//ds = new DERSet(new DERSequence(new DERTaggedObject(true, 1, new DERSequence(ocspDER))));
			}/* catch (OCSPResponseGenerationException e) {
				System.out.println("Issuer OCSP service not supported");
				ds = new DERSet(new DERSequence());
			} catch (IOException e) {
				e.printStackTrace();
				ds = new DERSet(new DERSequence());
			} catch (OCSPException e) {
				e.printStackTrace();
				ds = new DERSet(new DERSequence());
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
				ds = new DERSet(new DERSequence());
			}*/ catch (CRLResponseGenerationException e) {				
				e.printStackTrace();
				ds = new DERSet(new DERSequence());
			}
			Attribute pdf_revocation_info = new Attribute(new DERObjectIdentifier("1.2.840.113583.1.1.8"), ds);
			dv.add(pdf_revocation_info);
		}

		ds = new DERSet(new DERUTCTime(new Date()));
		Attribute signingTime = new Attribute(new DERObjectIdentifier("1.2.840.113549.1.9.5"), ds);
		dv.add(signingTime);

		// Data type
		ds = new DERSet(new DERObjectIdentifier("1.2.840.113549.1.7.1"));
		Attribute content_type = new Attribute(new DERObjectIdentifier("1.2.840.113549.1.9.3"), ds);
		dv.add(content_type);

		// Message Digest
		ds = new DERSet(new DEROctetString(hash));
		Attribute message_digest = new Attribute(new DERObjectIdentifier("1.2.840.113549.1.9.4"), ds);
		dv.add(message_digest);

		return new AttributeTable(dv);

	}

	/**
	 * 
	 * @param signedAttributes
	 * @param cert
	 * @param hash_algorithmID
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	@SuppressWarnings("unchecked")
	public static AttributeTable addCAdESAttributes(AttributeTable signedAttributes, X509Certificate cert, String hash_algorithmID) throws CMSSignatureGenerationException {		

		try {
			ESSCertID essCertid = new ESSCertID(MessageDigest.getInstance(AlgorithmIDtoOID(hash_algorithmID), "BC").digest(cert.getEncoded()));

			DERSet ds = new DERSet(new SigningCertificate(essCertid));
			Attribute signingCert = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, ds);

			DEREncodableVector dv = (DEREncodableVector)signedAttributes.toASN1EncodableVector();
			dv.add(signingCert);

			return new AttributeTable(dv);

		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			throw new CMSSignatureGenerationException(e);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new CMSSignatureGenerationException(e);
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new CMSSignatureGenerationException(e);
		}
	}

	/**
	 * 
	 * @param signedAttributes
	 * @param policyID
	 * @param policyHash
	 * @param algortithm_identifierID
	 * @return
	 * @throws CMSSignatureGenerationException
	 */
	public static AttributeTable addEPESAttributes(AttributeTable signedAttributes, String policyID, String policyHash, String algortithm_identifierID, String signerRole,List<String> commitment_identifiers) throws CMSSignatureGenerationException {		

		// signature policy identifier
		DEROctetString hashValue = new DEROctetString(policyHash.getBytes());
		OtherHashAlgAndValue sigPolicyHash = new OtherHashAlgAndValue(new AlgorithmIdentifier(AlgorithmIDtoOID(algortithm_identifierID)), hashValue);
		SignaturePolicyId sigPolicyId = new SignaturePolicyId(new DERObjectIdentifier(policyID), sigPolicyHash);

		SignaturePolicyIdentifier policyIdentifier = new SignaturePolicyIdentifier(sigPolicyId);

		DERSet ds = new DERSet(policyIdentifier);
		Attribute policyIdent = new Attribute(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, ds);

		DEREncodableVector dv;

		if(signedAttributes == null)
			dv = new ASN1EncodableVector();
		else
			dv = signedAttributes.toASN1EncodableVector();

		dv.add(policyIdent);

		// afegim el rol del signant
		if(signerRole != null){
			try{
				//			  SignerAttribute ::= SEQUENCE OF CHOICE {
				//			      claimedAttributes   [0] ClaimedAttributes,
				//			      certifiedAttributes [1] CertifiedAttributes }
				//
				//			  ClaimedAttributes ::= SEQUENCE OF Attribute
				//			  CertifiedAttributes ::= AttributeCertificate -- as defined in RFC 3281: see clause 4.1.

				//            Attribute ::= SEQUENCE {
				//                type      AttributeType,
				//                values    SET OF AttributeValue
				//                  -- at least one value is required
				//          }
				//
				//          AttributeType ::= OBJECT IDENTIFIER
				//
				//          AttributeValue ::= ANY DEFINED BY AttributeType
				DEROctetString obj = new DEROctetString(signerRole.getBytes());
				DERSet set = new DERSet(obj);
				Attribute attr = new Attribute(PKCSObjectIdentifiers.id_aa_ets_signerAttr, set);

				OutputStream os = new ByteArrayOutputStream();
				DERSequenceGenerator seqGen = new DERSequenceGenerator(os);
				seqGen.addObject(attr);
				byte[] byteArray = ((ByteArrayOutputStream)seqGen.getRawOutputStream()).toByteArray();
				seqGen.close();
				os.close();
				ASN1Sequence claimedAttr = (ASN1Sequence) ASN1Sequence.fromByteArray(byteArray);			
				SignerAttribute signerAttr = new SignerAttribute(claimedAttr);
				dv.add(signerAttr);

			}catch(Exception e){
				throw new CMSSignatureGenerationException(e.getMessage(),e.getCause());
			}
		}

		// ara afegim la informació del compromís en cas q n'hi hagi
		if(commitment_identifiers != null && commitment_identifiers.size()>0){
			//			id-aa-ets-commitmentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
			//				    us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 16}
			//
			//				commitment-type-indication attribute values have ASN.1 type
			//				CommitmentTypeIndication.
			//
			//				CommitmentTypeIndication ::= SEQUENCE {
			//				  commitmentTypeId CommitmentTypeIdentifier,
			//				  commitmentTypeQualifier SEQUENCE SIZE (1..MAX) OF CommitmentTypeQualifier OPTIONAL}
			//
			//				CommitmentTypeIdentifier ::= OBJECT IDENTIFIER
			//			
			//				CommitmentTypeQualifier ::= SEQUENCE {
			//				   commitmentTypeIdentifier   CommitmentTypeIdentifier,
			//				   qualifier                  ANY DEFINED BY commitmentTypeIdentifier }

			// FIXME: De moment es deixen els commitmentTypeQualifier a null (s'ha de parlar amb AiR).
			for(String commitmentId : commitment_identifiers){
				DERObjectIdentifier commitmentIdentifier = new DERObjectIdentifier(commitmentId);
				CommitmentTypeIndication commitment = new CommitmentTypeIndication(commitmentIdentifier);
				dv.add(commitment);
			}

		}

		return new AttributeTable(dv);
	}

	/**
	 * 
	 * @param ID
	 * @return
	 */
	private static String AlgorithmIDtoOID(String ID) {
		String OID = ID;

		if(ID.equals(SHA1))
			OID = SHA1OID;
		else if (ID.equals(SHA256))
			OID = SHA256OID;
		else if (ID.equals(SHA512))
			OID = SHA512OID;

		return OID;
	}

}
