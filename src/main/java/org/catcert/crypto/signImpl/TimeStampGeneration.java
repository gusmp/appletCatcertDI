package org.catcert.crypto.signImpl;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;

import lib.org.bouncycastle.asn1.ASN1InputStream;
import lib.org.bouncycastle.asn1.ASN1Sequence;
import lib.org.bouncycastle.asn1.DERBoolean;
import lib.org.bouncycastle.asn1.DEREncodableVector;
import lib.org.bouncycastle.asn1.DERInteger;
import lib.org.bouncycastle.asn1.DERObject;
import lib.org.bouncycastle.asn1.DERObjectIdentifier;
import lib.org.bouncycastle.asn1.DERSet;
import lib.org.bouncycastle.asn1.cms.Attribute;
import lib.org.bouncycastle.asn1.cms.AttributeTable;
import lib.org.bouncycastle.asn1.tsp.MessageImprint;
import lib.org.bouncycastle.asn1.tsp.TimeStampReq;
import lib.org.bouncycastle.asn1.tsp.TimeStampResp;
import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import lib.org.bouncycastle.cms.CMSException;
import lib.org.bouncycastle.cms.CMSSignedData;
import lib.org.bouncycastle.cms.SignerInformation;
import lib.org.bouncycastle.cms.SignerInformationStore;
import lib.org.bouncycastle.tsp.TSPException;
import lib.org.bouncycastle.tsp.TimeStampRequest;
import lib.org.bouncycastle.tsp.TimeStampResponse;
import lib.org.bouncycastle.tsp.TimeStampToken;
import lib.org.bouncycastle.tsp.TimeStampTokenInfo;

import org.catcert.crypto.utils.Utils;
import org.catcert.net.HTTPSender;
import org.catcert.net.HTTPSenderException;

/**
 * 
 * @author oburgos
 *
 */
public class TimeStampGeneration {

	/**
	 * 
	 * @param signedData
	 * @param proxySettings
	 * @return
	 * @throws TimeStampGenerationException
	 */
	@SuppressWarnings("unchecked")
	public static CMSSignedData addTimeStampToSignature (CMSSignedData signedData, HashMap<String, String> proxySettings, String tsa_url) throws TimeStampGenerationException{
		try {		
			Collection ss = signedData.getSignerInfos().getSigners();
			SignerInformation si = (SignerInformation) ss.iterator().next();

			TimeStampToken tok = getTimeStampToken(MessageDigest.getInstance("1.3.14.3.2.26", "BC").digest(si.getSignature()), proxySettings, tsa_url);

			ASN1InputStream asn1InputStream = new ASN1InputStream(tok.getEncoded());
			DERObject tstDER = asn1InputStream.readObject();
			DERSet ds = new DERSet(tstDER);

			Attribute a = new Attribute(new DERObjectIdentifier("1.2.840.113549.1.9.16.2.14"), ds);
			DEREncodableVector dv = new DEREncodableVector();
			dv.add(a);
			AttributeTable at = new AttributeTable(dv);
			si = SignerInformation.replaceUnsignedAttributes(si, at);
			ss.clear();
			ss.add(si);
			SignerInformationStore sis = new SignerInformationStore(ss);

			signedData = CMSSignedData.replaceSigners(signedData, sis);

			return signedData;
		} catch (IOException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (TimeStampGenerationException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param hash
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws TimeStampGenerationException
	 */
	@SuppressWarnings("unchecked")
	public static TimeStampToken getTimeStampToken(byte[] hash, HashMap<String, String> proxySettings, String tsa_url) throws TimeStampGenerationException {		
		try {						
			Random rand = new Random(new Date().getTime()); 
			String nonce = BigInteger.valueOf(rand.nextLong()).toString();	        

			TimeStampReq ts_req = createTimeStampRequest(hash, nonce, true);
			TimeStampResp ts_resp = sendTimestampRequest(ts_req, proxySettings, tsa_url);

			TimeStampResponse tsr = new TimeStampResponse(ts_resp);

			// Validate Response against request
			TimeStampRequest request = new TimeStampRequest(ts_req);			
			tsr.validate(request);

			// Recuperem el Token
			TimeStampToken token = tsr.getTimeStampToken();

			// Recuperem el tstInfo per validar-lo
			TimeStampTokenInfo info = token.getTimeStampInfo();

			// Comprovem els MessageImprint
			if (!new String(info.getMessageImprintDigest()).equals(new String(request.getMessageImprintDigest())))
				throw new TimeStampGenerationException("Error validant el MessageImprint del TSTInfo");

			// get the signing certificate
			CertStore certs = token.getCertificatesAndCRLs("Collection", "BC");
			X509Certificate TSA = (X509Certificate) ((Collection<X509Certificate>) certs.getCertificates(null)).iterator().next();

			CertificateFactory cf = CertificateFactory.getInstance("X509");
			// Generem el path sense el certificat del signant.
			CertPath TSA_root = cf.generateCertPath(Utils.getResource("EC-ACC.p7b"), "PKCS7");

			if (TSA == null)
				throw new TimeStampGenerationException("No hi ha cap certificat de TSA en la resposta");
			else {
				token.validate(TSA, "BC");				
				//verify the certificate
				TSA.verify(TSA_root.getCertificates().iterator().next().getPublicKey(), "BC");				
			}

			return token;
		} catch (TSPException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (TimeStampGenerationException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (CMSException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (CertStoreException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (SignatureException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param hashedData
	 * @param nonce
	 * @param requireCert
	 * @return
	 * @throws TimeStampGenerationException
	 */
	public static TimeStampReq createTimeStampRequest(byte[] hashedData, String nonce, boolean requireCert) throws TimeStampGenerationException {
		return createTimeStampRequest(hashedData, nonce, requireCert, "1.3.14.3.2.26" /* SHA1 */, null);
	}

	/**
	 * 
	 * @param hashedData
	 * @param nonce
	 * @param requireCert
	 * @param timestampPolicy
	 * @return
	 * @throws TimeStampGenerationException
	 */
	public static TimeStampReq createTimeStampRequestWithPolicy(byte[] hashedData, String nonce, boolean requireCert, String timestampPolicy) throws TimeStampGenerationException {
		return createTimeStampRequest(hashedData, nonce, requireCert, "1.3.14.3.2.26"  /*SHA1 */, timestampPolicy);
	}

	/**
	 * 
	 * @param hashedData
	 * @param nonce
	 * @param requireCert
	 * @param digestAlgorithm
	 * @param timestampPolicy
	 * @return
	 * @throws TimeStampGenerationException
	 */
	public static TimeStampReq createTimeStampRequest(byte[] hashedData, String nonce, boolean requireCert, String digestAlgorithm, String timestampPolicy) throws TimeStampGenerationException {
		TimeStampReq request;
		MessageImprint imprint = new MessageImprint(new AlgorithmIdentifier(digestAlgorithm), hashedData);

		request = new TimeStampReq(
				imprint, 
				timestampPolicy!=null?new DERObjectIdentifier(timestampPolicy):null, 
						nonce!=null?new DERInteger(nonce.getBytes()):null, 
								new DERBoolean(requireCert), 
								null
		);		

		return request;
	}

	/**
	 * 
	 * @param req
	 * @param proxySettings
	 * @return
	 * @throws TimeStampGenerationException
	 */
	public static TimeStampResp sendTimestampRequest(TimeStampReq req, HashMap<String, String> proxySettings, String tsa_url) throws TimeStampGenerationException {

		try {
			return sendData(req.getEncoded(), proxySettings, tsa_url);
		} catch (IOException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param dataToBeSent
	 * @param proxySettings
	 * @return
	 * @throws TimeStampGenerationException
	 */
	private static TimeStampResp sendData(byte[] dataToBeSent, HashMap<String, String> proxySettings, String tsa_url) throws TimeStampGenerationException{		
		InputStream response;
		TimeStampResp tspResp;

		try {
			System.out.println("Requesting RFC3161 TimeStamp");
			HTTPSender sender = new HTTPSender(proxySettings);
			response = sender.postTSQ(new URL(tsa_url), dataToBeSent);
			ASN1InputStream asn1Is = new ASN1InputStream(response);
			tspResp = new TimeStampResp((ASN1Sequence)asn1Is.readObject());
		} catch (HTTPSenderException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new TimeStampGenerationException(e.getMessage());
		}		
		return tspResp;
	}

	/**
	 * 
	 * @param signature
	 * @return
	 * @throws TimeStampGenerationException
	 */
	public static Calendar getDateFromTimeStampedCMS(byte[] signature) throws TimeStampGenerationException {
		return null;	
	}
}