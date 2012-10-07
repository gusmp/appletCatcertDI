package org.catcert.crypto.signImpl;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

import jonelo.jacksum.JacksumAPI;
import jonelo.jacksum.algorithm.AbstractChecksum;
import lib.com.lowagie.text.DocumentException;
import lib.com.lowagie.text.Image;
import lib.com.lowagie.text.Rectangle;
import lib.com.lowagie.text.pdf.AcroFields;
import lib.com.lowagie.text.pdf.PdfDate;
import lib.com.lowagie.text.pdf.PdfDicString;
import lib.com.lowagie.text.pdf.PdfDictionary;
import lib.com.lowagie.text.pdf.PdfName;
import lib.com.lowagie.text.pdf.PdfReader;
import lib.com.lowagie.text.pdf.PdfSignatureAppearance;
import lib.com.lowagie.text.pdf.PdfStamper;
import lib.com.lowagie.text.pdf.PdfString;

import org.catcert.crypto.utils.Utils;
import org.catcert.gui.PdfInputsDialog;
import org.catcert.psis.PSISValidation;
import org.catcert.psis.PSISValidationException;

import sun.security.provider.X509Factory;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;

/**
 * 
 * @author oburgos
 *
 */
public class PDFSignatureGeneration {

	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param dialog
	 * @param proxySettings
	 * @return
	 * @throws PDFSignatureGenerationException
	 * @throws PSISValidationException 
	 * @throws CertificateEncodingException 
	 */
	public static byte[] sign(File docToSign, KeyStore keyStore, String alias, char[] pin, int CAdES_type, Integer ReservedSpace, String hash_algorithm, PdfInputsDialog dialog, String signature_policy, String signature_policy_hash, String policy_hash_algorithm, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings) throws PDFSignatureGenerationException, CertificateEncodingException, PSISValidationException {
		return sign(docToSign, keyStore, alias, pin, CAdES_type, ReservedSpace, hash_algorithm, dialog, signature_policy, signature_policy_hash, policy_hash_algorithm, signerRole, commitment_identifiers, proxySettings, TsaUrl.PSIS_TSA_URL); 
	}
	
	
	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param dialog
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws PDFSignatureGenerationException
	 * @throws PSISValidationException 
	 * @throws CertificateEncodingException 
	 */
	public static byte[] sign(File docToSign, KeyStore keyStore, String alias, char[] pin, int CAdES_type, Integer ReservedSpace, String hash_algorithm, PdfInputsDialog dialog, String signature_policy, String signature_policy_hash, String policy_hash_algorithm, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url) throws PDFSignatureGenerationException, CertificateEncodingException, PSISValidationException {
		try {
			return sign(Utils.streamToByteArray(new FileInputStream(docToSign)), keyStore, alias, pin, CAdES_type, ReservedSpace, hash_algorithm, dialog, signature_policy, signature_policy_hash, policy_hash_algorithm, signerRole, commitment_identifiers, proxySettings, tsa_url);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (PDFSignatureGenerationException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param dialog
	 * @param proxySettings
	 * @return
	 * @throws PDFSignatureGenerationException
	 * @throws PSISValidationException 
	 * @throws CertificateEncodingException 
	 */
	@SuppressWarnings("unchecked")
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, int CAdES_type, Integer ReservedSpace, String hash_algorithm, PdfInputsDialog dialog, String signature_policy, String signature_policy_hash, String policy_hash_algorithm, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings) throws PDFSignatureGenerationException, CertificateEncodingException, PSISValidationException {
		return sign(docToSign, keyStore, alias, pin, CAdES_type, ReservedSpace, hash_algorithm, dialog, signature_policy, signature_policy_hash, policy_hash_algorithm, signerRole, commitment_identifiers, proxySettings, TsaUrl.PSIS_TSA_URL);
	}

	/**
	 * 
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param dialog
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws PDFSignatureGenerationException
	 * @throws PSISValidationException 
	 * @throws CertificateEncodingException 
	 */
	@SuppressWarnings("unchecked")
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, int CAdES_type, Integer ReservedSpace, String hash_algorithm, PdfInputsDialog dialog, String signature_policy, String signature_policy_hash, String policy_hash_algorithm, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url) throws PDFSignatureGenerationException, CertificateEncodingException, PSISValidationException {
		return sign(docToSign, keyStore, alias, pin, CAdES_type, ReservedSpace, hash_algorithm, dialog, signature_policy, signature_policy_hash, policy_hash_algorithm, signerRole, commitment_identifiers, proxySettings, tsa_url, false, null);
	}
	
	/**
	 * @param docToSign
	 * @param keyStore
	 * @param alias
	 * @param pin
	 * @param CAdES_type
	 * @param ReservedSpace
	 * @param hash_algorithm
	 * @param dialog
	 * @param signature_policy
	 * @param signature_policy_hash
	 * @param policy_hash_algorithm
	 * @param proxySettings
	 * @param tsa_url
	 * @param psisValidation
	 * @param requiredNif
	 * @return
	 * @throws PDFSignatureGenerationException
	 * @throws CertificateEncodingException
	 * @throws PSISValidationException
	 */
	@SuppressWarnings("unchecked")
	public static byte[] sign(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, int CAdES_type, Integer ReservedSpace, String hash_algorithm, PdfInputsDialog dialog, String signature_policy, String signature_policy_hash, String policy_hash_algorithm, String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url, boolean psisValidation, String requiredNif) throws PDFSignatureGenerationException, CertificateEncodingException, PSISValidationException {

		byte[] output = null;
		Object[] result;

		//document a signar
		try {
			//clau privada
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pin);

			//Recuperem la cadena de certificats
			Certificate[] certificationChain = keyStore.getCertificateChain(alias);
			if (certificationChain == null)
				certificationChain = new Certificate[] {(X509Certificate)keyStore.getCertificate(alias)};

			//validació del certificat contra PSIS
			if(psisValidation && certificationChain!=null && certificationChain[0]!=null){
				PSISValidation validator = new PSISValidation(requiredNif, proxySettings);
				boolean validCert = validator.Validate(certificationChain[0].getEncoded());
				if(!validCert)
					throw new PSISValidationException(validator.getError());
			}

			// Obrim el document
			PdfReader reader = new PdfReader(docToSign);

			// Creem la sortida
			ByteArrayOutputStream outt = new ByteArrayOutputStream();

			// Creem la signatura i com es representa
			PdfStamper stp = PdfStamper.createSignature(reader, outt, '\0', null, true);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();
			sap.setCrypto(privateKey, certificationChain, null, PdfSignatureAppearance.SELF_SIGNED);

			// Recuperem els camps de signatura disponibles per a poder-lo seleccionar o en generem un de nou
			AcroFields af = reader.getAcroFields();
			ArrayList names = af.getBlankSignatureNames();
			
			result = dialog.run(names, !af.getSignatureNames().isEmpty());
			switch((Integer)result[0]) {
			case 0: //No fer res
				return null;
			case 1: //Signatura visible
				if(!names.isEmpty()) { //Camps buits
					// Comprovem que el camp preseleccionat existeixi i estigui buit. Sinó excepció.
					String signatureField = (String)result[1];
					if(names.contains(signatureField))
						sap.setVisibleSignature(signatureField);
					else
						throw new PDFSignatureGenerationException("El camp de signatura " + signatureField + " no és buit o no existeix."); 
				}
				else {  //No camps buits, signatura nova visible
					HashMap<String, Integer> coordinates = (HashMap<String, Integer>)result[7];
					
					if(coordinates != null) {
						int pageNumber = coordinates.get("page_number").intValue();
						if(pageNumber == 0)
							pageNumber = reader.getNumberOfPages(); // last page
						
						sap.setVisibleSignature(new Rectangle(
								coordinates.get("llx").floatValue(), //lower left x 
								coordinates.get("lly").floatValue(), //lower left y
								coordinates.get("urx").floatValue(), //upper right x
								coordinates.get("ury").floatValue()), //upper right y
								pageNumber, null); //page number, null fieldname
					}						
					else{
						sap.setVisibleSignature(new Rectangle(100, 100, 200, 200), 1, null);
					}
				}
				// Si insertem imatge de signatura
				String imageb64 = (String)result[6];
				if (imageb64 != null) {
					try {
						byte[] image = javax.xml.bind.DatatypeConverter.parseBase64Binary(imageb64);
						sap.setSignatureGraphic(Image.getInstance(image));
						sap.setRender(PdfSignatureAppearance.SignatureRenderGraphicAndDescription);
					}
					catch (Throwable e){
						System.out.println("Error introduint la imatge de la signatura.");
					};
				}
				break;
			case 2: //Signatura no visible
				break;
			}			

			Calendar cal = Calendar.getInstance();
			PdfDictionary dic = new PdfDictionary();
			dic.put(PdfName.TYPE, PdfName.SIG);
			dic.put(PdfName.FILTER, PdfName.ADOBE_PPKLITE);
			dic.put(PdfName.SUBFILTER, new PdfName("adbe.pkcs7.detached"));
			dic.put(PdfName.M, new PdfDate(cal));
			dic.put(PdfName.NAME, new PdfString(Utils.getCN((X509Certificate) certificationChain[0], "subject")));
			dic.put(new PdfName("Prop_Build"), new PdfDicString("<</Filter<</Name/Adobe.PPKLite/Date(Jul 11 2008 09:11:15)>>/App<</Name/CATCert/REx(Eina Web de Signature-e v1.9)/TrustedMode true>>>>"));
			// reason & location
			if(!((String) result[4]).equalsIgnoreCase("")) {
				sap.setReason((String) result[4]);
				dic.put(PdfName.REASON, new PdfString((String) result[4]));
			}
			if(!((String) result[5]).equalsIgnoreCase("")) {
				sap.setLocation((String) result[5]);				
				dic.put(PdfName.LOCATION, new PdfString((String) result[5]));
			}			

			sap.setCryptoDictionary(dic);

			HashMap exc = new HashMap();

			// Espai a reservar, depenent de la signatura...
			if (ReservedSpace == null) {
				// CMS
				if (CAdES_type == CMSSignatureGeneration.CMS)
					ReservedSpace = new Integer(0x6502);
					// ReservedSpace = new Integer(0x96002); // Si volem afegir info de revocació
				// CAdES
				else
					ReservedSpace = new Integer(0x7A120); // Sense info de revocació
					// ReservedSpace = new Integer(0x13002);
					// ReservedSpace = new Integer(0x12C002); // Si volem afegir info de revocació
				
				exc.put(PdfName.CONTENTS, ReservedSpace*2+2);
			}				

			exc.put(PdfName.CONTENTS, ReservedSpace*2+2);

			// Si volem generar una MDP
			sap.setCertificationLevel((Integer)result[2]);
			
			sap.preClose(exc);

			// Recuperem les dades a signar
			//byte[] data = MessageDigest.getInstance(hash_algorithm, "BC").digest(Utils.streamToByteArray(sap.getRangeStream()));
			//substituim la crida enterior per una crida a JackSum: ens permet calcular eficientment el hash de documents pesats
			AbstractChecksum checksum = JacksumAPI.getChecksumInstance("sha1");
			checksum.reset();
			checksum.update(Utils.streamToByteArray(sap.getRangeStream()));
			byte[] data = checksum.getByteArray();
			
			// Generem la signatura i no afegim la info de revocació (paràmetre pdf d'atributs signats = false!)
			byte[] ssig = CMSSignatureGeneration.signHash(data, keyStore, alias, pin, (Boolean)result[3], CAdES_type, CMSSignatureGeneration.buildAuthenticatedAttributes(data, (X509Certificate)certificationChain[0], false, proxySettings), hash_algorithm, signature_policy, signature_policy_hash, policy_hash_algorithm, signerRole, commitment_identifiers, proxySettings, tsa_url);

			if(ssig == null)
				return null;

			//byte[] outc = new byte[(ReservedSpace-2) / 2];
			byte[] outc = new byte[ReservedSpace];
			System.arraycopy(ssig, 0, outc, 0, ssig.length);
			PdfDictionary dic2 = new PdfDictionary();

			dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));			

			// Tanquem i guardem el nou document
			sap.close(dic2);
			output = outt.toByteArray();
			outt.close();

			return output;

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException("L'entrada no és un document PDF vàlid: " + e.getMessage());
		} catch (DocumentException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException("L'entrada no és un document PDF vàlid: " + e.getMessage());
		} catch (CMSSignatureGenerationException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
//		} catch (NoSuchProviderException e) {
//			e.printStackTrace();
//			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (PSISValidationException e) {
			e.printStackTrace();
			throw new PSISValidationException(e.getMessage());
		} catch (Throwable e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		}

	}
	
	@SuppressWarnings("unchecked")
	public static byte[] signHSM(byte[] docToSign, KeyStore keyStore, String alias, char[] pin, int CAdES_type, Integer ReservedSpace, 
			String hash_algorithm, PdfInputsDialog dialog, String signature_policy, String signature_policy_hash, String policy_hash_algorithm, 
			String signerRole, List<String> commitment_identifiers, HashMap<String, String> proxySettings, String tsa_url, 
			boolean psisValidation, String requiredNif, String certificatePath ) 
	throws PDFSignatureGenerationException, CertificateEncodingException, PSISValidationException {

		byte[] output = null;
		Object[] result;

		//document a signar
		try {
			//clau privada
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pin);

			//Recuperem la cadena de certificats
			/*
			Certificate[] certificationChain = keyStore.getCertificateChain(alias);
			if (certificationChain == null)
				certificationChain = new Certificate[] {(X509Certificate)keyStore.getCertificate(alias)};

			//validació del certificat contra PSIS
			if(psisValidation && certificationChain!=null && certificationChain[0]!=null){
				PSISValidation validator = new PSISValidation(requiredNif, proxySettings);
				boolean validCert = validator.Validate(certificationChain[0].getEncoded());
				if(!validCert)
					throw new PSISValidationException(validator.getError());
			}
			*/
			
			//HSM: recuperar certificat que fa la signatura. Ara el certificat no está al keystore
			InputStream inStream = new FileInputStream(certificatePath);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate x509Certificate = (X509Certificate)cf.generateCertificate(inStream);
			inStream.close();
			Certificate[] certificationChain = new Certificate[1];
			certificationChain[0] = x509Certificate;
			
			
			if (psisValidation) {
				try 
				{
					PSISValidation validator = new PSISValidation(requiredNif, proxySettings);
					boolean validCert = validator.Validate(x509Certificate.getEncoded());
					if(!validCert)
						throw new PSISValidationException(validator.getError());
				} catch (CertificateException exc) {
					throw new PSISValidationException(exc.toString());
				} catch (PSISValidationException exc) {
					throw new PSISValidationException(exc.toString());
				}
			}

			// Obrim el document
			PdfReader reader = new PdfReader(docToSign);

			// Creem la sortida
			ByteArrayOutputStream outt = new ByteArrayOutputStream();

			// Creem la signatura i com es representa
			PdfStamper stp = PdfStamper.createSignature(reader, outt, '\0', null, true);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();
			//HSM: indicar que la signatura es realitzará amb el mateix proveidor on s'emmagatzema 
			//     la clau privada
			sap.setProvider(keyStore.getProvider().getName());
			sap.setCrypto(privateKey, certificationChain, null, PdfSignatureAppearance.SELF_SIGNED);

			// Recuperem els camps de signatura disponibles per a poder-lo seleccionar o en generem un de nou
			AcroFields af = reader.getAcroFields();
			ArrayList names = af.getBlankSignatureNames();
			
			result = dialog.run(names, !af.getSignatureNames().isEmpty());
			switch((Integer)result[0]) {
			case 0: //No fer res
				return null;
			case 1: //Signatura visible
				if(!names.isEmpty()) { //Camps buits
					// Comprovem que el camp preseleccionat existeixi i estigui buit. Sinó excepció.
					String signatureField = (String)result[1];
					if(names.contains(signatureField))
						sap.setVisibleSignature(signatureField);
					else
						throw new PDFSignatureGenerationException("El camp de signatura " + signatureField + " no és buit o no existeix."); 
				}
				else {  //No camps buits, signatura nova visible
					HashMap<String, Integer> coordinates = (HashMap<String, Integer>)result[7];
					
					if(coordinates != null) {
						int pageNumber = coordinates.get("page_number").intValue();
						if(pageNumber == 0)
							pageNumber = reader.getNumberOfPages(); // last page
						
						sap.setVisibleSignature(new Rectangle(
								coordinates.get("llx").floatValue(), //lower left x 
								coordinates.get("lly").floatValue(), //lower left y
								coordinates.get("urx").floatValue(), //upper right x
								coordinates.get("ury").floatValue()), //upper right y
								pageNumber, null); //page number, null fieldname
					}						
					else{
						sap.setVisibleSignature(new Rectangle(100, 100, 200, 200), 1, null);
					}
				}
				// Si insertem imatge de signatura
				String imageb64 = (String)result[6];
				if (imageb64 != null) {
					try {
						//byte[] image = new BASE64Decoder().decodeBuffer(imageb64);
						byte[] image = javax.xml.bind.DatatypeConverter.parseBase64Binary(imageb64);
						sap.setSignatureGraphic(Image.getInstance(image));
						sap.setRender(PdfSignatureAppearance.SignatureRenderGraphicAndDescription);
					}
					catch (Throwable e){
						System.out.println("Error introduint la imatge de la signatura.");
					};
				}
				break;
			case 2: //Signatura no visible
				break;
			}			

			Calendar cal = Calendar.getInstance();
			PdfDictionary dic = new PdfDictionary();
			dic.put(PdfName.TYPE, PdfName.SIG);
			dic.put(PdfName.FILTER, PdfName.ADOBE_PPKLITE);
			dic.put(PdfName.SUBFILTER, new PdfName("adbe.pkcs7.detached"));
			dic.put(PdfName.M, new PdfDate(cal));
			//dic.put(PdfName.NAME, new PdfString(Utils.getCN((X509Certificate) certificationChain[0], "subject")));
			dic.put(PdfName.NAME, new PdfString(Utils.getCN(x509Certificate, "subject")));
			dic.put(new PdfName("Prop_Build"), new PdfDicString("<</Filter<</Name/Adobe.PPKLite/Date(Jul 11 2008 09:11:15)>>/App<</Name/CATCert/REx(Eina Web de Signature-e v1.9)/TrustedMode true>>>>"));
			// reason & location
			if(!((String) result[4]).equalsIgnoreCase("")) {
				sap.setReason((String) result[4]);
				dic.put(PdfName.REASON, new PdfString((String) result[4]));
			}
			if(!((String) result[5]).equalsIgnoreCase("")) {
				sap.setLocation((String) result[5]);				
				dic.put(PdfName.LOCATION, new PdfString((String) result[5]));
			}			

			sap.setCryptoDictionary(dic);

			HashMap exc = new HashMap();

			// Espai a reservar, depenent de la signatura...
			if (ReservedSpace == null) {
				// CMS
				if (CAdES_type == CMSSignatureGeneration.CMS)
					ReservedSpace = new Integer(0x6502);
					// ReservedSpace = new Integer(0x96002); // Si volem afegir info de revocació
				// CAdES
				else
					ReservedSpace = new Integer(0x7A120); // Sense info de revocació
					// ReservedSpace = new Integer(0x13002);
					// ReservedSpace = new Integer(0x12C002); // Si volem afegir info de revocació
				
				exc.put(PdfName.CONTENTS, ReservedSpace*2+2);
			}				

			exc.put(PdfName.CONTENTS, ReservedSpace*2+2);

			// Si volem generar una MDP
			sap.setCertificationLevel((Integer)result[2]);
			
			sap.preClose(exc);

			// Recuperem les dades a signar
			//byte[] data = MessageDigest.getInstance(hash_algorithm, "BC").digest(Utils.streamToByteArray(sap.getRangeStream()));
			//substituim la crida enterior per una crida a JackSum: ens permet calcular eficientment el hash de documents pesats
			AbstractChecksum checksum = JacksumAPI.getChecksumInstance("sha1");
			checksum.reset();
			checksum.update(Utils.streamToByteArray(sap.getRangeStream()));
			byte[] data = checksum.getByteArray();
			
			// Generem la signatura i no afegim la info de revocació (paràmetre pdf d'atributs signats = false!)
			//byte[] ssig = CMSSignatureGeneration.signHash(data, keyStore, alias, pin, (Boolean)result[3], CAdES_type, CMSSignatureGeneration.buildAuthenticatedAttributes(data, x509Certificate, false, proxySettings), hash_algorithm, signature_policy, signature_policy_hash, policy_hash_algorithm, signerRole, commitment_identifiers, proxySettings, tsa_url);
			byte[] ssig = CMSSignatureGeneration.signHashHSM(data, keyStore, alias, pin, (Boolean)result[3], 
					CAdES_type, 
					CMSSignatureGeneration.buildAuthenticatedAttributes(data, x509Certificate, false, proxySettings), 
					hash_algorithm, signature_policy, signature_policy_hash, policy_hash_algorithm, 
					signerRole, commitment_identifiers, proxySettings, tsa_url,false, null,
					x509Certificate);
			
			if(ssig == null)
				return null;

			//byte[] outc = new byte[(ReservedSpace-2) / 2];
			byte[] outc = new byte[ReservedSpace];
			System.arraycopy(ssig, 0, outc, 0, ssig.length);
			PdfDictionary dic2 = new PdfDictionary();

			dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));			

			// Tanquem i guardem el nou document
			sap.close(dic2);
			output = outt.toByteArray();
			outt.close();

			return output;

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException("L'entrada no és un document PDF vàlid: " + e.getMessage());
		} catch (DocumentException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException("L'entrada no és un document PDF vàlid: " + e.getMessage());
		} catch (CMSSignatureGenerationException e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
//		} catch (NoSuchProviderException e) {
//			e.printStackTrace();
//			throw new PDFSignatureGenerationException(e.getMessage());
		} catch (PSISValidationException e) {
			e.printStackTrace();
			throw new PSISValidationException(e.getMessage());
		} catch (Throwable e) {
			e.printStackTrace();
			throw new PDFSignatureGenerationException(e.getMessage());
		}

	}
}