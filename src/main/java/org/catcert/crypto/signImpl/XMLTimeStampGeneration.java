package org.catcert.crypto.signImpl;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import lib.org.apache.xml.security.utils.XMLUtils;

import org.catcert.crypto.utils.Utils;
import org.catcert.net.HTTPSender;
import org.catcert.net.HTTPSenderException;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

//import sun.misc.BASE64Encoder;

/**
 * 
 * @author oburgos
 *
 */
public class XMLTimeStampGeneration {

	/**
	 * 
	 * @param SignatureValue
	 * @param proxySettings
	 * @param tsa_url
	 * @return
	 * @throws XMLTimeStampGenerationException
	 */
	public static Element getXMLTimeStamp(byte[] SignatureValue, HashMap<String, String> proxySettings, String tsa_url) throws XMLTimeStampGenerationException{		
		try {
			//String hash = new BASE64Encoder().encode(SignatureValue);
			String hash = Utils.printBase64Binary(SignatureValue);
			 
			String template = new String(Utils.streamToByteArray(Utils.getResource("XMLTSCreation.xml")));			
			template = template.replaceFirst("DIGEST_TO_TIMESTAMP", hash);

			InputStream TS = sendXMLTimeStampRequest(template.getBytes(), proxySettings, tsa_url);

			// Parsejat del document
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			docFactory.setAttribute("http://java.sun.com/"+"xml/jaxp/properties/schemaLanguage", "http://www.w3.org/2001/XMLSchema");
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			Element soapelement = docBuilder.parse(TS).getDocumentElement();
			Element Tstinfo = XMLUtils.selectElement(soapelement, "http://www.w3.org/2000/09/xmldsig#", "Signature");

			return Tstinfo;

		} catch (IOException e) {
			e.printStackTrace();
			throw new XMLTimeStampGenerationException(e.getMessage());
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			throw new XMLTimeStampGenerationException(e.getMessage());
		} catch (SAXException e) {
			e.printStackTrace();
			throw new XMLTimeStampGenerationException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param TSRequest
	 * @param proxySettings
	 * @return
	 * @throws XMLTimeStampGenerationException
	 */
	private static InputStream sendXMLTimeStampRequest(byte[] TSRequest, HashMap<String, String> proxySettings, String tsa_url) throws XMLTimeStampGenerationException{		
		InputStream response;

		try {
			System.out.println("Requesting XML TimeStamp");
			HTTPSender sender = new HTTPSender(proxySettings);
			response = sender.postXML(new URL(tsa_url), TSRequest);

		} catch (HTTPSenderException e) {
			e.printStackTrace();
			throw new XMLTimeStampGenerationException(e.getMessage());
		} catch (MalformedURLException e) {
			e.printStackTrace();
			throw new XMLTimeStampGenerationException(e.getMessage());
		}		
		return response;
	}
}