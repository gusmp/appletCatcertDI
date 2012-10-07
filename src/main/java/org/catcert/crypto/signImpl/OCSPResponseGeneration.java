package org.catcert.crypto.signImpl;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.util.HashMap;
import java.util.Vector;

import lib.org.bouncycastle.asn1.DERObjectIdentifier;
import lib.org.bouncycastle.asn1.DEROctetString;
import lib.org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import lib.org.bouncycastle.asn1.x509.X509Extension;
import lib.org.bouncycastle.asn1.x509.X509Extensions;
import lib.org.bouncycastle.ocsp.BasicOCSPResp;
import lib.org.bouncycastle.ocsp.CertificateID;
import lib.org.bouncycastle.ocsp.OCSPException;
import lib.org.bouncycastle.ocsp.OCSPReq;
import lib.org.bouncycastle.ocsp.OCSPReqGenerator;
import lib.org.bouncycastle.ocsp.OCSPResp;
import lib.org.bouncycastle.ocsp.SingleResp;

import org.catcert.crypto.utils.Utils;
import org.catcert.net.HTTPSender;
import org.catcert.net.HTTPSenderException;

public class OCSPResponseGeneration {

	public static OCSPResp generateOCSPResponse(String issuerCN, BigInteger serialNumber, HashMap<String, String> proxySettings) throws OCSPResponseGenerationException {
		try {
			
			byte[] issuerNameHash = Utils.getKnownIssuerNameDigest(issuerCN);
			byte[] issuerPublicKeyHash = Utils.getKnownIssuerPublicKeyDigest(issuerCN);
			
			// Generate the id for the certificate we are looking for
			CertificateID id = new CertificateID(CertificateID.HASH_SHA1, issuerNameHash, issuerPublicKeyHash, serialNumber);

			// basic request generation with nonce
			OCSPReqGenerator gen = new OCSPReqGenerator();

			gen.addRequest(id);

			// create details for nonce extension
			BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
			Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
			Vector<X509Extension> values = new Vector<X509Extension>();

			oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));

			gen.setRequestExtensions(new X509Extensions(oids, values));

			OCSPReq request = gen.generate();
			OCSPResp response = sendOCSPReq(request.getEncoded(), proxySettings);
			
			BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
			SingleResp[] responses = basicResponse.getResponses();
			System.out.println("Certificate status: " + responses[0].getCertStatus());
			
			return response;
			
		} catch (OCSPException e) {
			throw new OCSPResponseGenerationException(e.getMessage());
		} catch (IOException e) {
			throw new OCSPResponseGenerationException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param dataToBeSent
	 * @param proxySettings
	 * @return
	 * @throws OCSPResponseGenerationException
	 */
	private static OCSPResp sendOCSPReq(byte[] dataToBeSent, HashMap<String, String> proxySettings) throws OCSPResponseGenerationException{		
		InputStream response;
		OCSPResp ocspResp;

		try {
			HTTPSender sender = new HTTPSender(proxySettings);
			response = sender.postOCSPQ(new URL("http://ocsp.catcert.net"), dataToBeSent);
			ocspResp = new OCSPResp(response);
		} catch (HTTPSenderException e) {
			e.printStackTrace();
			throw new OCSPResponseGenerationException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new OCSPResponseGenerationException(e.getMessage());
		}		
		return ocspResp;
	}
}