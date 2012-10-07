package org.catcert.crypto.signImpl;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import lib.org.bouncycastle.asn1.ASN1InputStream;
import lib.org.bouncycastle.asn1.DERObject;

import org.catcert.crypto.utils.Utils;
import org.catcert.net.HTTPSender;
import org.catcert.net.HTTPSenderException;

import sun.security.x509.CRLDistributionPointsExtension;
import sun.security.x509.DistributionPoint;
import sun.security.x509.GeneralName;
import sun.security.x509.X509CertImpl;

public class CRLResponseGeneration {

	public static DERObject generateCRLResponse(X509Certificate certToValidate, HashMap<String, String> proxySettings) throws CRLResponseGenerationException {

		try {

			byte[] derBytes = certToValidate.getExtensionValue("2.5.29.31");
			if(derBytes != null)				
			{
				// Si hi ha cache, utilitzar-la, sinó descarregar la CRL de nou:
				String filename = Utils.getCN(certToValidate, "issuer");
				try {
					InputStream crlFile = Utils.readTempFile(filename);
					DERObject crlObject = new ASN1InputStream(crlFile).readObject();
					if (crlObject!=null)
						return crlObject;
				}
				catch(FileNotFoundException e) {
					System.out.println(e.getMessage());
					System.out.println("Downloading CRL...");

				}

				CRLDistributionPointsExtension distPoints = X509CertImpl.toImpl(certToValidate).getCRLDistributionPointsExtension();

				Enumeration<String> dpsEnu = distPoints.getElements();
				HTTPSender downloader = new HTTPSender(proxySettings);

				while(dpsEnu.hasMoreElements()) {
					List<GeneralName> crl_urls = ((DistributionPoint)((ArrayList<?>)distPoints.get(((String)dpsEnu.nextElement()))).get(0)).getFullName().names();

					for (Iterator<GeneralName> url_iterator = crl_urls.listIterator(); url_iterator.hasNext();) {
						String URI = url_iterator.next().toString().substring(9);
						InputStream crlStream = downloader.getMethod(new URL(URI));
						DERObject crlObject = new ASN1InputStream(crlStream).readObject();
						if (crlObject!=null) {
							Utils.copyToTempPath(crlObject.getDEREncoded(), Utils.getCN(certToValidate, "issuer"), 2000);
							return crlObject;
						}
							
					}	
				}
			}

			throw new CRLResponseGenerationException("Error retrieving CRL information from certificate");

		} catch (CertificateException e) {
			throw new CRLResponseGenerationException(e);
		} catch (IOException e) {
			throw new CRLResponseGenerationException(e);
		} catch (HTTPSenderException e) {
			throw new CRLResponseGenerationException(e);
		}
	}
}
