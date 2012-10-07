package org.catcert.crypto.signImpl;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import jonelo.jacksum.JacksumAPI;
import jonelo.jacksum.algorithm.AbstractChecksum;
import lib.org.apache.xml.security.Init;
import lib.org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import lib.org.apache.xml.security.c14n.CanonicalizationException;
import lib.org.apache.xml.security.exceptions.XMLSecurityException;
import lib.org.apache.xml.security.signature.ObjectContainer;
import lib.org.apache.xml.security.signature.ReferenceNotInitializedException;
import lib.org.apache.xml.security.signature.XMLSignature;
import lib.org.apache.xml.security.signature.XMLSignatureException;
import lib.org.apache.xml.security.signature.XMLSignatureInput;
import lib.org.apache.xml.security.transforms.Transforms;
import lib.org.apache.xml.security.utils.Base64;
import lib.org.apache.xml.security.utils.Constants;
import lib.org.apache.xml.security.utils.DigesterOutputStream;
import lib.org.apache.xml.security.utils.UnsyncBufferedOutputStream;
import lib.org.apache.xml.security.utils.XMLUtils;

import org.catcert.crypto.utils.Utils;
import org.catcert.psis.PSISValidation;
import org.catcert.psis.PSISValidationException;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

//import sun.misc.BASE64Encoder;

/**
 * 
 * @author oburgos
 * @author aciffone
 *
 */
public class XMLdsigGeneration  {

	// Signature modes
	public static final int enveloped = 1;
	public static final int enveloping = 2;
	public static final int detached_document = 3;
	public static final int detached_document_hash = 4;

	// XAdES level
	public static final int XMLdSIG = 1;
	public static final int XADES_BES = 2;
	public static final int XADES_T = 3;
	public static final int XADES_C = 4;

	// Hash algorithm URN's
	private static final String SHA1URN = "http://www.w3.org/2000/09/xmldsig#sha1";
	private static final String SHA256URN = "http://www.w3.org/2001/04/xmlenc#sha256";
	private static final String SHA512URN = "http://www.w3.org/2001/04/xmlenc#sha512";

	// Hash algorithm Id's
	private static final String SHA1 = "SHA-1";
	private static final String SHA256 = "SHA-256";
	private static final String SHA512 = "SHA-512";

	// URIs
	private static final String XAdESv122NS = "http://uri.etsi.org/01903/v1.2.2#";


	/**
	 * Genera una signatura XML per a un document (XML o binari).
	 * Els modes disponibles són enveloping (la signatura incorpora al document 
	 * original dins de la seva estructura), enveloped (el document afegeix 
	 * la signatura a dins de la seva estructura), i detached utilitzant el 
	 * hash del document original.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param mode
	 * @param hashAlgorithmOID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmOID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign(File docToSign, KeyStore keyStore, String alias, char[] pin, int mode, String hashAlgorithmOID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmOID, String policyQualifier, String SignerRole,List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings) throws XMLdsigGenerationException, PSISValidationException {
		return sign(docToSign, keyStore, alias, pin, mode, hashAlgorithmOID, XAdESLevel, policy, policyHash, policyHashAlgorithmOID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, TsaUrl.PSIS_AVS_URL);
	}

	/**
	 * Genera una signatura XML per a un document (XML o binari).
	 * Els modes disponibles són enveloping (la signatura incorpora al document 
	 * original dins de la seva estructura), enveloped (el document afegeix 
	 * la signatura a dins de la seva estructura), i detached utilitzant el 
	 * hash del document original.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param mode
	 * @param hashAlgorithmOID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmOID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign(File docToSign, KeyStore keyStore, String alias, char[] pin, int mode, String hashAlgorithmOID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmOID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String tsa_url) throws XMLdsigGenerationException, PSISValidationException {

		try {
			return sign(Utils.streamToByteArray(new FileInputStream(docToSign)), keyStore, alias, pin, mode, hashAlgorithmOID, XAdESLevel, policy, policyHash, policyHashAlgorithmOID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, tsa_url);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		}
	}

	/**
	 * Genera una signatura XML per a un document (XML o binari).
	 * Els modes disponibles són enveloping (la signatura incorpora al document 
	 * original dins de la seva estructura), enveloped (el document afegeix 
	 * la signatura a dins de la seva estructura), i detached utilitzant el 
	 * hash del document original.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param mode
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, int mode, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings) throws XMLdsigGenerationException, PSISValidationException {
		return sign(docToSign, keyStore, alias, pin, mode, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, TsaUrl.PSIS_AVS_URL);
	}


	/**
	 * Genera una signatura XML per a un document (XML o binari).
	 * Els modes disponibles són enveloping (la signatura incorpora al document 
	 * original dins de la seva estructura), enveloped (el document afegeix 
	 * la signatura a dins de la seva estructura), i detached utilitzant el 
	 * hash del document original.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param mode
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, int mode, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String tsa_url) throws XMLdsigGenerationException, PSISValidationException {
		return sign(docToSign, keyStore, alias, pin, mode, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, tsa_url, false, null);
	}
	/**
	 * Genera una signatura XML per a un document (XML o binari).
	 * Els modes disponibles són enveloping (la signatura incorpora al document 
	 * original dins de la seva estructura), enveloped (el document afegeix 
	 * la signatura a dins de la seva estructura), i detached utilitzant el 
	 * hash del document original.
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param mode
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param tsa_url
	 * @param psisValidation
	 * @param requiredNif
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, int mode, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String tsa_url, boolean psisValidation, String requiredNif) throws XMLdsigGenerationException, PSISValidationException {

		InputStream documentToSign = Utils.byteArrayToStream(docToSign);
		String canonicalTransform = canonWithComm ? Transforms.TRANSFORM_C14N_WITH_COMMENTS :  Transforms.TRANSFORM_C14N_OMIT_COMMENTS;
		XMLSignature sig = null;
		Document docToBeSigned = null;
		byte[] output = null;

		try{
			//certificat
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

			Init.init();

			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			docFactory.setAttribute("http://java.sun.com/"+"xml/jaxp/properties/schemaLanguage", "http://www.w3.org/2001/XMLSchema");
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			// Signature algorithm
			String sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			if(hashAlgorithmID.equals(SHA1))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			else if (hashAlgorithmID.equals(SHA256))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
			else if (hashAlgorithmID.equals(SHA512))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;

			if (mode == enveloping) {
				// Generem el document a signar
				docToBeSigned = docBuilder.newDocument();
				// Generem l'objecte signatura en blanc amb el document XML on ha d'anar.

				sig = new XMLSignature(docToBeSigned, "", sigAlgorithm);
				sig.setSignatureValueId("DocumentSignatureValue");

				// Recuperem l'element de la signatura i l'afegim al document a signar.
				Element element = sig.getElement();
				element.setAttribute("Id", "Signature");
				docToBeSigned.appendChild(element);

				// Creem l'objecte transforms, per poder instanciar les transformades necessàries.
				Transforms transforms = new Transforms(docToBeSigned);

				// SignedInfo ID
				sig.getSignedInfo().setId("SignedInfo");

				// Creem el KeyInfo
				sig.addKeyInfo((X509Certificate) cert);
				sig.addKeyInfo(cert.getPublicKey());
				sig.getKeyInfo().setId("KeyInfo");
				if(protectKeyInfo)
					sig.addDocument("#KeyInfo");

				// Generem les signed properties de XAdES
				if (XAdESLevel > XMLdSIG) // XADES-BES, signed properties
					createXAdESObject(docToBeSigned, sig, cert, hashAlgorithmID, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs);

				// Generem els objects i les references del document a signar
				Element objeto = docToBeSigned.createElement("ds:Object");
				objeto.setAttribute("Id", "Object-1");

				//Comportament segons si dtbsigned es XML o no
				Element originalXML = parseXML(documentToSign);
				if(originalXML != null) {
					transforms.addTransform(canonicalTransform);
					objeto.appendChild(objeto.getOwnerDocument().importNode(originalXML, true));
				}
				else {
					transforms.addTransform(Transforms.TRANSFORM_BASE64_DECODE);
					//TODO modificació per ATC (problemes d'incompatibilitat amb llibreries aplicació SIGNO)
					//objeto.setTextContent(Base64.encode(docToSign));
					Node text = docToBeSigned.createTextNode(Base64.encode(docToSign));
					objeto.appendChild(text);
				}
				element.appendChild(objeto);
				sig.addDocument("#Object-1", transforms, AlgorithmIDtoURN(hashAlgorithmID), "SignedDataObject-Reference-1", null);

				// Generem la signatura XMLdsig o XADES-BES
				sig.sign(privateKey);

				// Generem les unsigned propeties
				if (XAdESLevel > XADES_BES) // XADES-T
					createXADES_T_Properties(docToBeSigned, sig, hashAlgorithmID, cert, proxySettings, tsa_url);

				if (XAdESLevel > XADES_T) // XADES-C
					createXADES_T_Properties(docToBeSigned, sig, hashAlgorithmID, cert, proxySettings, tsa_url);
				//createXADES_C_Properties(docToBeSigned, sig, cert);

				// Serialitzem i exportem la signatura
				ByteArrayOutputStream outt = new ByteArrayOutputStream();
				XMLUtils.outputDOMc14nWithComments(docToBeSigned, outt);
				output = outt.toByteArray();
				outt.close();
			}
			else if (mode == enveloped){
				//Enveloped signature
				docToBeSigned = docBuilder.parse(documentToSign);

				Element root = docToBeSigned.getDocumentElement();

				sig = new XMLSignature(docToBeSigned, "", sigAlgorithm);
				Element element = sig.getElement();
				element.setAttribute("Id", "Signature");
				root.appendChild(element);
				sig.setSignatureValueId("DocumentSignatureValue");
				
				// SignedInfo ID
				sig.getSignedInfo().setId("SignedInfo");

				Transforms transforms = new Transforms(docToBeSigned);
				transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
				transforms.addTransform(canonicalTransform);
				sig.addDocument("", transforms, AlgorithmIDtoURN(hashAlgorithmID),"SignedDataObject-enveloped",null);
				sig.addKeyInfo((X509Certificate) cert);
				sig.addKeyInfo(cert.getPublicKey());
				sig.getKeyInfo().setId("KeyInfo");
				if(protectKeyInfo)
					sig.addDocument("#KeyInfo");

				// Generem les signed properties de XAdES
				if (XAdESLevel > XMLdSIG) // XADES-BES, signed properties
					createXAdESObject(docToBeSigned, sig, cert, hashAlgorithmID, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs);

				// Generem la signatura XMLdsig o XAdES-BES
				sig.sign(privateKey);

				// Generem les unsigned propeties
				if (XAdESLevel > XADES_BES) // XAdES-T
					createXADES_T_Properties(docToBeSigned, sig, hashAlgorithmID, cert, proxySettings, tsa_url);

				if (XAdESLevel > XADES_T) // XAdES-C
					createXADES_T_Properties(docToBeSigned, sig, hashAlgorithmID, cert, proxySettings, tsa_url);
				//createXADES_C_Properties(docToBeSigned, sig, cert);

				ByteArrayOutputStream outt = new ByteArrayOutputStream();
				XMLUtils.outputDOMc14nWithComments(docToBeSigned, outt);
				output = outt.toByteArray();
				outt.close();
			}
			else if (mode == detached_document) {
				Vector<byte[]> docHash = new Vector<byte[]>();
				//Comportament segons si dtbsigned es XML o no
				Element originalXML = parseXML(documentToSign);
				if(originalXML != null) {

					MessageDigestAlgorithm mda = MessageDigestAlgorithm.getInstance(originalXML.getOwnerDocument(), AlgorithmIDtoURN(hashAlgorithmID));					
					mda.reset();
					DigesterOutputStream diOs = new DigesterOutputStream(mda);
					OutputStream os = new UnsyncBufferedOutputStream(diOs);
					XMLSignatureInput signatureInput = new XMLSignatureInput((Node) originalXML);
					Document transformDoc = docBuilder.newDocument();
					Transforms c14nTrans = new Transforms(transformDoc);
					transformDoc.appendChild(c14nTrans.getElement());
					c14nTrans.addTransform(canonicalTransform);
					XMLSignatureInput c14nResult = c14nTrans.performTransforms(signatureInput);
					c14nResult.updateOutputStream(os);
					os.flush();

					//Canonicalizer c14n = Canonicalizer.getInstance("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
					//byte[] bt = c14n.canonicalizeSubtree(originalXML);
					//docHash.add(MessageDigest.getInstance(hashAlgorithmID).digest(bt));
					docHash.add(diOs.getDigestValue());
				}
				else{
					//docHash.add(MessageDigest.getInstance(hashAlgorithmID).digest(docToSign));
					//substituim la crida enterior per una crida a JackSum: ens permet calcular eficientment el hash de documents pesats
					AbstractChecksum checksum = JacksumAPI.getChecksumInstance("sha1");
					checksum.reset();
					checksum.update(docToSign);
					docHash.add(checksum.getByteArray());
				}

				output = sign_nDetached(docHash, keyStore, alias, pin, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, tsa_url);
			}

			return output;

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (SAXException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (TimeStampGenerationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (DOMException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (XMLTimeStampGenerationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (PSISValidationException e) {
			e.printStackTrace();
			throw new PSISValidationException(e.getMessage());
		} catch (Throwable e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		}
	}


	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param browserCookie
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign_nFilesEnveloping(Vector<File> docToSign, KeyStore keyStore, String alias, char[] pin, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String browserCookie) throws XMLdsigGenerationException, PSISValidationException {
		return sign_nFilesEnveloping(docToSign, keyStore, alias, pin, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions,commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, TsaUrl.PSIS_AVS_URL, browserCookie);
	}

	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param tsa_url
	 * @param browserCookie
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign_nFilesEnveloping(Vector<File> docToSign, KeyStore keyStore, String alias, char[] pin, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String tsa_url, String browserCookie) throws XMLdsigGenerationException, PSISValidationException {
		Vector<byte[]> documentToSign = new Vector<byte[]>();

		try {

			for (int i = 0; i<docToSign.size(); i++)				
				documentToSign.add(Utils.streamToByteArray(new FileInputStream(docToSign.get(i))));

			return sign_nEnveloping(documentToSign, keyStore, alias, pin, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, tsa_url);

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign_nEnveloping(Vector<byte[]> docToSign, KeyStore keyStore, String alias, char[] pin, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole , List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs,  boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings) throws XMLdsigGenerationException, PSISValidationException {
		return sign_nEnveloping(docToSign, keyStore, alias, pin, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, TsaUrl.PSIS_AVS_URL);
	}


	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign_nEnveloping(Vector<byte[]> docToSign, KeyStore keyStore, String alias, char[] pin, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String tsa_url) throws XMLdsigGenerationException, PSISValidationException {
		return sign_nEnveloping(docToSign, keyStore, alias, pin, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, tsa_url, false, null);
	}	

	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param tsa_url
	 * @param psisValidation
	 * @param requiredNif
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign_nEnveloping(Vector<byte[]> docToSign, KeyStore keyStore, String alias, char[] pin, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String tsa_url, boolean psisValidation, String requiredNif) throws XMLdsigGenerationException, PSISValidationException {

		String canonicalTransform = canonWithComm ? Transforms.TRANSFORM_C14N_WITH_COMMENTS :  Transforms.TRANSFORM_C14N_OMIT_COMMENTS;
		XMLSignature sig = null;
		Document docToBeSigned = null;
		byte[] output = null;

		try{			
			//certificat
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

			Init.init();

			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			docFactory.setAttribute("http://java.sun.com/"+"xml/jaxp/properties/schemaLanguage", "http://www.w3.org/2001/XMLSchema");
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			// Signature algorithm
			String sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			if(hashAlgorithmID.equals(SHA1))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			else if (hashAlgorithmID.equals(SHA256))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
			else if (hashAlgorithmID.equals(SHA512))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;

			// Generem el document a signar
			docToBeSigned = docBuilder.newDocument();
			// Generem l'objecte signatura en blanc amb el document XML on ha d'anar.
			sig = new XMLSignature(docToBeSigned, "", sigAlgorithm);
			sig.setSignatureValueId("DocumentSignatureValue");

			// Recuperem l'element de la signatura i l'afegim al document a signar.
			Element element = sig.getElement();
			element.setAttribute("Id", "Signature");
			docToBeSigned.appendChild(element);

			// Creem l'objecte transforms, per poder instanciar les transformades necessàries.
			Transforms transforms = new Transforms(docToBeSigned);

			// SignedInfo ID
			sig.getSignedInfo().setId("SignedInfo");

			// Creem el KeyInfo
			sig.addKeyInfo((X509Certificate) cert);
			sig.addKeyInfo(cert.getPublicKey());
			sig.getKeyInfo().setId("KeyInfo");
			if(protectKeyInfo)
				sig.addDocument("#KeyInfo");

			// Generem les signed properties de XAdES
			if (XAdESLevel > XMLdSIG) // XADES-BES, signed properties
				createXAdESObject(docToBeSigned, sig, cert, hashAlgorithmID, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs);

			// Generem els objects i les references dels documents a signar
			for (int i = 0; i < docToSign.size(); i++){

				InputStream documentToSign = Utils.byteArrayToStream(docToSign.get(i));

				Element objeto = docToBeSigned.createElement("ds:Object");
				objeto.setAttribute("Id", "Object-" + (i + 1));

				//Comportament segons si dtbsigned es XML o no
				Element originalXML = parseXML(documentToSign);
				if(originalXML != null) {
					transforms.addTransform(canonicalTransform);					
					objeto.appendChild(objeto.getOwnerDocument().importNode(originalXML, true));
				}
				else {
					transforms.addTransform(Transforms.TRANSFORM_BASE64_DECODE);					
					//TODO modificació per ATC (problemes d'incompatibilitat amb llibreries aplicació SIGNO)
					//objeto.setTextContent(Base64.encode(docToSign.get(i)));
					Node text = docToBeSigned.createTextNode(Base64.encode(docToSign.get(i)));
					objeto.appendChild(text);
				}					
				element.appendChild(objeto);
				sig.addDocument("#Object-" + (i + 1), null, AlgorithmIDtoURN(hashAlgorithmID), "SignedDataObject-Reference-" + (i + 1), null);					
			}

			// Generem la signatura XMLdsig o XADES-BES/EPES
			sig.sign(privateKey);

			// Generem les unsigned propeties
			if (XAdESLevel > XADES_BES) // XADES-T
				createXADES_T_Properties(docToBeSigned, sig, hashAlgorithmID, cert, proxySettings, tsa_url);

			if (XAdESLevel > XADES_T) // XADES-C
				createXADES_T_Properties(docToBeSigned, sig, hashAlgorithmID, cert, proxySettings, tsa_url);
			//createXADES_C_Properties(docToBeSigned, sig, cert);

			// Serialitzem i exportem la signatura
			ByteArrayOutputStream outt = new ByteArrayOutputStream();
			XMLUtils.outputDOMc14nWithComments(docToBeSigned, outt);
			output = outt.toByteArray();
			outt.close();

			return output;

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (SAXException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (TimeStampGenerationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (DOMException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (XMLTimeStampGenerationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (PSISValidationException e) {
			e.printStackTrace();
			throw new PSISValidationException(e.getMessage());
		} catch (Throwable e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		}		
	}	

	/**
	 * Genera una signatura XML detached amb referències que contenen els resums dels documents signats.
	 * 
	 * @param docHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign_nDetached(Vector<byte[]> docHash, KeyStore keyStore, String alias, char[] pin, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings) throws XMLdsigGenerationException, PSISValidationException {				
		return sign_nDetached(docHash, keyStore, alias, pin, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, TsaUrl.PSIS_AVS_URL);
	}


	/**
	 * Genera una signatura XML detached amb referències que contenen els resums dels documents signats.
	 * 
	 * @param docHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign_nDetached(Vector<byte[]> docHash, KeyStore keyStore, String alias, char[] pin, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String tsa_url) throws XMLdsigGenerationException, PSISValidationException {
		return sign_nDetached(docHash, keyStore, alias, pin, hashAlgorithmID, XAdESLevel, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs, canonWithComm, protectKeyInfo, proxySettings, tsa_url, false, null);
	}

	/**
	 * Genera una signatura XML detached amb referències que contenen els resums dels documents signats.
	 * 
	 * @param docHash
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param hashAlgorithmID
	 * @param XAdESLevel
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param SignerRole
	 * @param canonWithComm
	 * @param protectKeyInfo
	 * @param proxySettings
	 * @param tsa_url
	 * @param psisValidation
	 * @param requiredNif
	 * @return
	 * @throws XMLdsigGenerationException
	 * @throws PSISValidationException 
	 */
	public static byte[] sign_nDetached(Vector<byte[]> docHash, KeyStore keyStore, String alias, char[] pin, String hashAlgorithmID, int XAdESLevel, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String SignerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs, boolean canonWithComm, boolean protectKeyInfo, HashMap<String, String> proxySettings, String tsa_url, boolean psisValidation, String requiredNif) throws XMLdsigGenerationException, PSISValidationException {				
		try {
			// certificat
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

			Init.init();

			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			docFactory.setAttribute("http://java.sun.com/"+"xml/jaxp/properties/schemaLanguage", "http://www.w3.org/2001/XMLSchema");
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			// Signature algorithm
			String sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			if(hashAlgorithmID.equals(SHA1))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			else if (hashAlgorithmID.equals(SHA256))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
			else if (hashAlgorithmID.equals(SHA512))
				sigAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;

			// Generem el document a signar
			Document docToBeSigned = docBuilder.newDocument();
			// Generem l'objecte signatura en blanc amb el document XML on ha d'anar.
			XMLSignature sig = new XMLSignature(docToBeSigned, "", sigAlgorithm);
			sig.setSignatureValueId("DocumentSignatureValue");

			// Recuperem l'element de la signatura i l'afegim al document a signar.
			Element element = sig.getElement();
			element.setAttribute("Id", "Signature");
			docToBeSigned.appendChild(element);

			// SignedInfo ID
			sig.getSignedInfo().setId("SignedInfo");

			// Creem el KeyInfo
			sig.addKeyInfo((X509Certificate) cert);
			sig.addKeyInfo(cert.getPublicKey());
			sig.getKeyInfo().setId("KeyInfo");
			if(protectKeyInfo)
				sig.addDocument("#KeyInfo");

			// Generem les signed properties de XAdES
			if (XAdESLevel > XMLdSIG) // XADES-BES, signed properties
				createXAdESObject(docToBeSigned, sig, cert, hashAlgorithmID, policy, policyHash, policyHashAlgorithmID, policyQualifier, SignerRole, commitmentIds, commitmentDescriptions, commitmentObjRefs);

			// Creem la reference al document detached i li passem el hash
			for (int i = 0; i < docHash.size(); i++)
				sig.addDocument("DetachedObjectReference-" + (i + 1), null, AlgorithmIDtoURN(hashAlgorithmID), "SignedDataObject-Reference", null, docHash.get(i));

			// Generem la signatura XMLdsig o XADES-BES
			sig.sign(privateKey);

			// Generem les unsigned propeties
			if (XAdESLevel > XADES_BES) // XAdES-T
				createXADES_T_Properties(docToBeSigned, sig, hashAlgorithmID, cert, proxySettings, tsa_url);

			if (XAdESLevel > XADES_T) // XAdES-C
				createXADES_T_Properties(docToBeSigned, sig, hashAlgorithmID, cert, proxySettings, tsa_url);
			//createXADES_C_Properties(docToBeSigned, sig, cert);

			// Serialitzem i exportem la signatura
			ByteArrayOutputStream outt = new ByteArrayOutputStream();
			XMLUtils.outputDOMc14nWithComments(docToBeSigned, outt);
			byte[] output = outt.toByteArray();
			outt.close();

			return output;

		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (SAXException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (TimeStampGenerationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (DOMException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (XMLTimeStampGenerationException e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		} catch (PSISValidationException e) {
			e.printStackTrace();
			throw new PSISValidationException(e.getMessage());
		} catch (Throwable e) {
			e.printStackTrace();
			throw new XMLdsigGenerationException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param docToBeSigned
	 * @param sig
	 * @param cert
	 * @param hashAlgorithmID
	 * @param policy
	 * @param policyHash
	 * @param policyHashAlgorithmID
	 * @param policyQualifier
	 * @param signerRole
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws SAXException
	 * @throws IOException
	 * @throws XMLSecurityException
	 */
	private static void createXAdESObject(Document docToBeSigned, XMLSignature sig, X509Certificate cert, String hashAlgorithmID, String policy, String policyHash, String policyHashAlgorithmID, String policyQualifier, String signerRole, List<String> commitmentIds, List<String> commitmentDescriptions, List<String> commitmentObjRefs) throws CertificateEncodingException, NoSuchAlgorithmException, SAXException, IOException, XMLSecurityException {

		ObjectContainer object = new ObjectContainer(docToBeSigned);
		// QualifyingProperties
		XMLUtils.createDSctx(docToBeSigned, "xades", XAdESv122NS);
		Element QualifyingProperties = docToBeSigned.createElementNS(XAdESv122NS, "xades:QualifyingProperties");
		QualifyingProperties.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xades", XAdESv122NS);
		QualifyingProperties.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds", Constants.SignatureSpecNS);
		QualifyingProperties.setAttribute("Target", "#Signature");
		QualifyingProperties.setAttribute("Id", "QualifyingProperties");
		object.appendChild(QualifyingProperties);
		// SignedProperties
		Element SignedProperties = docToBeSigned.createElementNS(XAdESv122NS, "xades:SignedProperties");
		SignedProperties.setAttribute("Id", "SignedProperties");
		QualifyingProperties.appendChild(SignedProperties);
		// SignedSignatureProperties
		Element SignedSignatureProperties = docToBeSigned.createElementNS(XAdESv122NS, "xades:SignedSignatureProperties");
		SignedProperties.appendChild(SignedSignatureProperties);
		// SigningTime
		Element SigningTime = docToBeSigned.createElementNS(XAdESv122NS, "xades:SigningTime");
		Node time = docToBeSigned.createTextNode(Utils.getCurrentDate());
		SigningTime.appendChild(time);
		SignedSignatureProperties.appendChild(SigningTime);
		// SigningCertificate
		Element SigningCertificate = docToBeSigned.createElementNS(XAdESv122NS, "xades:SigningCertificate");
		SignedSignatureProperties.appendChild(SigningCertificate);
		// Cert
		Element Cert = docToBeSigned.createElementNS(XAdESv122NS, "xades:Cert");
		SigningCertificate.appendChild(Cert);
		// CertDigest
		Element CertDigest = docToBeSigned.createElementNS(XAdESv122NS, "xades:CertDigest");
		Cert.appendChild(CertDigest);
		// DigestMethod
		Element digestMethod = docToBeSigned.createElementNS(Constants.SignatureSpecNS, "ds:DigestMethod");
		digestMethod.setAttribute("Algorithm", AlgorithmIDtoURN(hashAlgorithmID));
		CertDigest.appendChild(digestMethod);
		// DigestValue
		Element digestValue = docToBeSigned.createElementNS(Constants.SignatureSpecNS, "ds:DigestValue");
		//Node digestValueText = docToBeSigned.createTextNode(new BASE64Encoder().encode(MessageDigest.getInstance(hashAlgorithmID).digest(cert.getEncoded())));
		Node digestValueText = docToBeSigned.createTextNode(Utils.printBase64Binary(MessageDigest.getInstance(hashAlgorithmID).digest(cert.getEncoded())));
		digestValue.appendChild(digestValueText);
		CertDigest.appendChild(digestValue);
		// IssuerSerial
		Element IssuerSerial = docToBeSigned.createElementNS(XAdESv122NS, "xades:IssuerSerial");
		Cert.appendChild(IssuerSerial);
		// X509IssuerName
		Element X509IssuerName = docToBeSigned.createElementNS(Constants.SignatureSpecNS, "ds:X509IssuerName");
		Node X509IssuerNameValue = docToBeSigned.createTextNode(cert.getIssuerX500Principal().getName(X500Principal.RFC2253));		
		X509IssuerName.appendChild(X509IssuerNameValue);
		IssuerSerial.appendChild(X509IssuerName);
		// X509IssuerSerialNumber
		Element X509SerialNumber = docToBeSigned.createElementNS(Constants.SignatureSpecNS, "ds:X509SerialNumber");
		Node X509SerialNumberValue = docToBeSigned.createTextNode(cert.getSerialNumber().toString());
		X509SerialNumber.appendChild(X509SerialNumberValue);
		IssuerSerial.appendChild(X509SerialNumber);

		// EPES
		if(policy != null && policyHash != null) {
			//SignaturePolicyIdentifier
			Element SignaturePolicyIdentifier = docToBeSigned.createElementNS(XAdESv122NS, "xades:SignaturePolicyIdentifier");
			SignedSignatureProperties.appendChild(SignaturePolicyIdentifier);
			//SignaturePolicyId
			Element SignaturePolicyId = docToBeSigned.createElementNS(XAdESv122NS, "xades:SignaturePolicyId");
			SignaturePolicyIdentifier.appendChild(SignaturePolicyId);
			//SigPolicyId
			Element SigPolicyId = docToBeSigned.createElementNS(XAdESv122NS, "xades:SigPolicyId");
			SignaturePolicyId.appendChild(SigPolicyId);
			// identifier
			Element identifier = docToBeSigned.createElementNS(XAdESv122NS, "xades:Identifier");
			Node identifierTxt = docToBeSigned.createTextNode(policy);		
			identifier.appendChild(identifierTxt);
			SigPolicyId.appendChild(identifier);
			// TODO Hauriem d'afegir un paràmetre també pel description... tot i q no afecta a la creació o validació de les epes
			// Seria igual q afegir l'identifier 

			//SigPolicyHash
			Element SigPolicyHash = docToBeSigned.createElementNS(XAdESv122NS, "xades:SigPolicyHash");
			SignaturePolicyId.appendChild(SigPolicyHash);
			//DigestMethod
			Element SigDigestMethod = docToBeSigned.createElementNS(Constants.SignatureSpecNS, "ds:DigestMethod");
			SigDigestMethod.setAttribute("Algorithm", AlgorithmIDtoURN(policyHashAlgorithmID));
			SigPolicyHash.appendChild(SigDigestMethod);
			//DigestValue
			Element SigDigestValue = docToBeSigned.createElementNS(Constants.SignatureSpecNS, "ds:DigestValue");
			Node SigDigestValueText = docToBeSigned.createTextNode(policyHash);
			SigDigestValue.appendChild(SigDigestValueText);
			SigPolicyHash.appendChild(SigDigestValue);
			// to avoid nullPointerExceptions during signature creation
			// only add policyQualifiers if we have a no null value
			if(policyQualifier != null){
				//SigPolicyQualifiers
				Element SigPolicyQualifiers = docToBeSigned.createElementNS(XAdESv122NS, "xades:SigPolicyQualifiers");
				SignaturePolicyId.appendChild(SigPolicyQualifiers);
				//SigPolicyQualifier
				Element SigPolicyQualifier = docToBeSigned.createElementNS(XAdESv122NS, "xades:SigPolicyQualifier");
				SigPolicyQualifiers.appendChild(SigPolicyQualifier);
				//SPURI
				Element SPURI = docToBeSigned.createElementNS(XAdESv122NS, "xades:SPURI");
				Node SPURIValueText = docToBeSigned.createTextNode(policyQualifier);
				SPURI.appendChild(SPURIValueText);
				SigPolicyQualifier.appendChild(SPURI);
			}
		}

		// SignerRole
		if(signerRole != null) {
			//SignerRole
			Element SignerRole = docToBeSigned.createElementNS(XAdESv122NS, "xades:SignerRole");
			SignedSignatureProperties.appendChild(SignerRole);
			//ClaimedRoles
			Element ClaimedRoles = docToBeSigned.createElementNS(XAdESv122NS, "xades:ClaimedRoles");
			SignerRole.appendChild(ClaimedRoles);
			//ClaimedRoles
			Element ClaimedRole = docToBeSigned.createElementNS(XAdESv122NS, "xades:ClaimedRole");
			Node role = docToBeSigned.createTextNode(signerRole);
			ClaimedRole.appendChild(role);
			ClaimedRoles.appendChild(ClaimedRole);
		}

		// Commitment
		if(commitmentIds != null){

			// Commitments go inside SignedDataObjectProperties!!!
			// SignedDataObjectProperties
			Element SignedDataObjectProperties = docToBeSigned.createElementNS(XAdESv122NS, "xades:SignedDataObjectProperties");
			SignedProperties.appendChild(SignedDataObjectProperties);
			
			// commitmentIds
			for(int i=0;i<commitmentIds.size();i++){
				// CommitmentTypeId
				Element commitmentTypeIndication = docToBeSigned.createElementNS(XAdESv122NS, "xades:CommitmentTypeIndication");
				Element commitmentTypeId = docToBeSigned.createElementNS(XAdESv122NS,"xades:CommitmentTypeId");
				// Identifier
				Element commitmentIdentifier = docToBeSigned.createElementNS(XAdESv122NS, "xades:Identifier");
				Node identifier = docToBeSigned.createTextNode(commitmentIds.get(i));
				commitmentIdentifier.appendChild(identifier);
				commitmentTypeId.appendChild(commitmentIdentifier);

				try{
					// description
					Element commitmentDescription = docToBeSigned.createElementNS(XAdESv122NS, "xades:Description");
					Node description = docToBeSigned.createTextNode(commitmentDescriptions.get(i));
					commitmentDescription.appendChild(description);
					commitmentTypeId.appendChild(commitmentDescription);
				}catch(IndexOutOfBoundsException e){}

				commitmentTypeIndication.appendChild(commitmentTypeId);
				
				try{
					// ObjectReference
					Element objectReference = docToBeSigned.createElementNS(XAdESv122NS, "xades:ObjectReference");
					Node objectRef = docToBeSigned.createTextNode(commitmentObjRefs.get(i));
					objectReference.appendChild(objectRef);
					commitmentTypeIndication.appendChild(objectReference);					
				}catch(IndexOutOfBoundsException e){
					// AllSignedDataObject
					Element allSignedDataObject = docToBeSigned.createElementNS(XAdESv122NS, "xades:AllSignedDataObjects");
					commitmentTypeIndication.appendChild(allSignedDataObject);					
				}
							
				// put all in SignedDataObjectProperties
				SignedDataObjectProperties.appendChild(commitmentTypeIndication);

			}	
		}

		// Afegim les QualifyingProperties que contenen les SignedProperties
		sig.appendObject(object);

		// Creem una reference a les propietats signades XADES
		sig.addDocument("#SignedProperties", null, AlgorithmIDtoURN(hashAlgorithmID), "SignedProperties-Reference", "http://uri.etsi.org/01903/v1.2.2#SignedProperties");		
	}

	/**
	 * 
	 * @param docToBeSigned
	 * @param sig
	 * @param hashAlgorithmID
	 * @param cert
	 * @param proxySettings
	 * @param tsa_url
	 * @throws DOMException
	 * @throws XMLSignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws TimeStampGenerationException
	 * @throws XMLTimeStampGenerationException
	 * @throws CanonicalizationException
	 * @throws IOException
	 */
	public static void createXADES_T_Properties(Document docToBeSigned, XMLSignature sig, String hashAlgorithmID, X509Certificate cert, HashMap<String, String> proxySettings, String tsa_url) throws DOMException, XMLSignatureException, NoSuchAlgorithmException, NoSuchProviderException, TimeStampGenerationException, XMLTimeStampGenerationException, CanonicalizationException, IOException {
		/*		 
		 <xades:UnsignedProperties>
		 <xades:UnsignedSignatureProperties>
		 <xades:SignatureTimeStamp Id="id-fb30b33f-9ddc-45be-aba3-bf174dc4fa56">
		 <xades:Include referencedData="false" URI="#id-3a7e97b4-2c7e-4dd2-9b39-245ffbbee8ba"/>
		 <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
		 <xades:XMLTimeStamp>
		 <ds:Signature Id="id-1fd816a5-183c-44b2-b19c-34841b2a27b6">
		 ...
		 </ds:Signature>
		 </xades:XMLTimeStamp>
		 </xades:SignatureTimeStamp>
		 </xades:UnsignedSignatureProperties>
		 */

		// Creem les unsignedProperties (segell XML definit per OASIS)
		// Recuperem el node Qualifying Properties
		Element QualifyingProperties = XMLUtils.selectElement(docToBeSigned.getFirstChild(),XAdESv122NS, "QualifyingProperties");
		// UnSignedProperties
		Element UnSignedProperties = docToBeSigned.createElementNS(XAdESv122NS, "xades:UnsignedProperties");
		UnSignedProperties.setAttribute("Id", "UnsignedProperties");
		QualifyingProperties.appendChild(UnSignedProperties);
		// UnSignedSignatureProperties
		Element UnSignedSignatureProperties = docToBeSigned.createElementNS(XAdESv122NS, "xades:UnsignedSignatureProperties");
		UnSignedProperties.appendChild(UnSignedSignatureProperties);
		// SignatureTimeStamp				
		Element SignatureTimeStamp = docToBeSigned.createElementNS(XAdESv122NS, "xades:SignatureTimeStamp");
		SignatureTimeStamp.setAttribute("Id", "SignatureTimeStamp");
		UnSignedSignatureProperties.appendChild(SignatureTimeStamp);
		// Include
		Element Include = docToBeSigned.createElementNS(XAdESv122NS, "xades:Include");
		Include.setAttribute("referencedData", "false");
		Include.setAttribute("URI", "#DocumentSignatureValue");
		SignatureTimeStamp.appendChild(Include);
		// CanonicalizationMethod		
		Element CanonicalizationMethod = docToBeSigned.createElementNS(Constants.SignatureSpecNS, "ds:CanonicalizationMethod");
		CanonicalizationMethod.setAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		SignatureTimeStamp.appendChild(CanonicalizationMethod);
		// XMLTimeStamp
		Element XMLTimeStamp = docToBeSigned.createElementNS(XAdESv122NS, "xades:XMLTimeStamp");
		XMLTimeStamp.setAttribute("xmlns:dss", "urn:oasis:names:tc:dss:1.0:core:schema");
		SignatureTimeStamp.appendChild(XMLTimeStamp);
		// Generem i afegim l'XML TimeStamp en forma de <ds:signature>		
		XMLTimeStamp.appendChild(XMLTimeStamp.getOwnerDocument().importNode(XMLTimeStampGeneration.getXMLTimeStamp(calculateDigest(sig, hashAlgorithmID), proxySettings, tsa_url), true));
	}

	/**
	 * 
	 * @param docToBeSigned
	 * @param sig
	 * @param cert
	 */
	public static void createXADES_C_Properties(Document docToBeSigned, XMLSignature sig, X509Certificate cert) {

		/*
		 * Dins de les <xades:UnsignedSignatureProperties>
		 * 
		 <xades:CompleteCertificateRefs Id="id-4ee914a3-5e26-464e-853e-e62e87d2cce1">
		 <xades:CertRefs>
		 <xades:Cert>
		 <xades:CertDigest>
		 <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
		 <ds:DigestValue>CVWrcqg7NzTDiQfhH9KVZkJxVuY=</ds:DigestValue>
		 </xades:CertDigest>
		 <xades:IssuerSerial>
		 <ds:X509IssuerName>CN=EC-GENCAT,OU=Generalitat de Catalunya,OU=Vegeu https://www.catcert.net/verCIC-1  (c)03,OU=Serveis Publics de Certificacio ECV-1,O=Agencia Catalana de Certificacio (NIF Q-0801176-I),C=ES</ds:X509IssuerName>
		 <ds:X509SerialNumber>148786221414740922626357724534625015094</ds:X509SerialNumber>
		 </xades:IssuerSerial>
		 </xades:Cert>
		 <xades:Cert>
		 <xades:CertDigest>
		 <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
		 <ds:DigestValue>8Ldbt5MRsOXQEPHtjcfljxW+aP0=</ds:DigestValue>
		 </xades:CertDigest>
		 <xades:IssuerSerial>
		 <ds:X509IssuerName>CN=EC-ACC,OU=Jerarquia Entitats de Certificacio Catalanes,OU=Vegeu https://www.catcert.net/verarrel (c)03,OU=Serveis Publics de Certificacio,O=Agencia Catalana de Certificacio (NIF Q-0801176-I),C=ES</ds:X509IssuerName>
		 <ds:X509SerialNumber>43517894977975666787701712876307936290</ds:X509SerialNumber>
		 </xades:IssuerSerial>
		 </xades:Cert>
		 </xades:CertRefs>
		 </xades:CompleteCertificateRefs>
		 <xades:CompleteRevocationRefs Id="id-9ab56a27-a0b3-4869-bc1b-92456bdb05e0">
		 <xades:CRLRefs>
		 <xades:CRLRef>
		 <xades:DigestAlgAndValue>
		 <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
		 <ds:DigestValue>9PrgdAkD+GrDTjjfR0vh3w4O6K4=</ds:DigestValue>
		 </xades:DigestAlgAndValue>
		 <xades:CRLIdentifier>
		 <xades:Issuer>CN=EC-SAFP,OU=Secretaria d'Administracio i Funcio Publica,OU=Vegeu https://www.catcert.net/verCIC-2   (c)03,OU=Serveis Publics de Certificacio ECV-2,L=Passatge de la Concepcio 11 08008 Barcelona,O=Agencia Catalana de Certificacio (NIF Q-0801176-I),C=ES</xades:Issuer>
		 <xades:IssueTime>2006-09-18T11:18:42.000Z</xades:IssueTime>
		 <xades:Number>857</xades:Number>
		 </xades:CRLIdentifier>
		 </xades:CRLRef>
		 <xades:CRLRef>
		 <xades:DigestAlgAndValue>
		 <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
		 <ds:DigestValue>qUpu1LKUwAbPLzW6zVUf7DUrfUQ=</ds:DigestValue>
		 </xades:DigestAlgAndValue>
		 <xades:CRLIdentifier>
		 <xades:Issuer>CN=EC-GENCAT,OU=Generalitat de Catalunya,OU=Vegeu https://www.catcert.net/verCIC-1  (c)03,OU=Serveis Publics de Certificacio ECV-1,O=Agencia Catalana de Certificacio (NIF Q-0801176-I),C=ES</xades:Issuer>
		 <xades:IssueTime>2004-12-22T10:09:19.000Z</xades:IssueTime>
		 <xades:Number>1</xades:Number>
		 </xades:CRLIdentifier>
		 </xades:CRLRef>
		 <xades:CRLRef>
		 <xades:DigestAlgAndValue>
		 <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
		 <ds:DigestValue>t5LTiMY8FEtMMtXn7WITY2sy9l8=</ds:DigestValue>
		 </xades:DigestAlgAndValue>
		 <xades:CRLIdentifier>
		 <xades:Issuer>CN=EC-ACC,OU=Jerarquia Entitats de Certificacio Catalanes,OU=Vegeu https://www.catcert.net/verarrel (c)03,OU=Serveis Publics de Certificacio,O=Agencia Catalana de Certificacio (NIF Q-0801176-I),C=ES</xades:Issuer>
		 <xades:IssueTime>2004-12-22T10:02:29.000Z</xades:IssueTime>
		 <xades:Number>1</xades:Number>
		 </xades:CRLIdentifier>
		 </xades:CRLRef>
		 </xades:CRLRefs>
		 </xades:CompleteRevocationRefs>
		 */	
	}

	/**
	 * 
	 * @param documents
	 * @param hashAlgorithmID
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static Vector<byte[]> calculateVectorContentsHash(Vector<byte[]> documents, String hashAlgorithmID) throws NoSuchAlgorithmException {
		Vector<byte[]> docHash = new Vector<byte[]>();

		for(int i=0; i<documents.size(); i++)
			docHash.add(MessageDigest.getInstance(hashAlgorithmID).digest(documents.get(i)));

		return docHash;
	}

	/**
	 * 
	 * @param sig
	 * @param hashAlgorithmID
	 * @return
	 * @throws ReferenceNotInitializedException
	 * @throws XMLSignatureException
	 * @throws CanonicalizationException
	 * @throws IOException
	 */
	private static byte[] calculateDigest(XMLSignature sig, String hashAlgorithmID) throws ReferenceNotInitializedException, XMLSignatureException, CanonicalizationException, IOException {

		Document signature = sig.getDocument();
		Element signatureValue = XMLUtils.selectElement(signature.getDocumentElement(), Constants.SignatureSpecNS, "SignatureValue");

		MessageDigestAlgorithm mda = MessageDigestAlgorithm.getInstance(signature, AlgorithmIDtoURN(hashAlgorithmID));

		mda.reset();
		DigesterOutputStream diOs = new DigesterOutputStream(mda);
		OutputStream os = new UnsyncBufferedOutputStream(diOs);
		XMLSignatureInput output = new XMLSignatureInput(signatureValue);         
		output.updateOutputStream(os);
		os.flush();

		return diOs.getDigestValue();
	}

	/**
	 * Returns true if content is a valid XML document.
	 * 
	 * @param content
	 * @return
	 */
	private static Element parseXML(InputStream content) {			
		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder;
		Document originalXML;
		try {
			docBuilder = docFactory.newDocumentBuilder();
			originalXML = docBuilder.parse(content);
		} catch (Exception e) {			
			return null;
		}
		return originalXML.getDocumentElement();
	}

	/**
	 * 
	 * @param ID
	 * @return
	 */
	private static String AlgorithmIDtoURN(String ID) {

		String hashURN = ID;

		if(ID.equals(SHA1))
			hashURN = SHA1URN;
		else if (ID.equals(SHA256))
			hashURN = SHA256URN;
		else if (ID.equals(SHA512))
			hashURN = SHA512URN;

		return hashURN;
	}
}