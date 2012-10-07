package org.catcert.psis;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import lib.org.bouncycastle.util.encoders.Base64;

import org.catcert.net.HTTPSender;
import org.catcert.net.HTTPSenderException;
import org.catcert.utils.AppletConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class PSISValidation {

	//HOST
	//PREPRODUCCIÓ
	//private static String HOST = "http://psisbeta.catcert.net/psis/catcert-test/dss";
	//PRODUCCIÓ
	private static String HOST = "http://psis.catcert.net/psis/catcert/dss";
	
	private String response = "";
	
	private String requiredNif;
	private String psisNif;
	private boolean isValidNif = true;
	
	HashMap<String, String> proxySettings;

	public PSISValidation() {
		this.requiredNif = null;
	}
	
	public PSISValidation(String requiredNif, HashMap<String, String> proxySettings) {
		this.requiredNif = requiredNif;
		if(proxySettings!=null){
			this.proxySettings = proxySettings;
		}
	}

	/**
	 * Validació del certificat del signatari contra PSIS, i comprovació del NIF del signatari.
	 * @param cert certificat del signatari
	 * @param nif NIF del signatari
	 * @return true: vàlid ; false: no vàlid / error / NIF no permès
	 * @throws PSISValidationException 
	 */
	public boolean Validate(byte[] cert) throws PSISValidationException
	{
		this.response = sendRequest(cert);
		
		return response != null && response.indexOf(AppletConstants.PSIS_RESULTMAJOR_OK) > 0 && response.indexOf(AppletConstants.PSIS_RESULTMINOR_VALID) > 0 && this.isValidNif;
	}
	
	/**
	 * Retorna la resposta de PSIS com a String.
	 * @return resposta de PSIS com a String
	 */
	public String getResponse()
	{
		return this.response;
	}
	
	/**
	 * Retorna el NIF del certificat del signatari obtingut amb PSIS.
	 * @return NIF del certificar, o "null" si és nul
	 */
	public String getPsisNif(){
		return this.psisNif;
	}
	
	/**
	 * Envia al petició de validació de certificat contra PSIS. Retorna la resposta de PSIS com a String. 
	 * @param cert certificat a validar
	 * @return resposta de validació de PSIS com a String
	 * @throws IOException
	 * @throws PSISValidationException 
	 */
	private String sendRequest(byte[] cert) throws PSISValidationException
	{
		
		try{
			
			StringBuffer xml = new StringBuffer();
			
			xml.append("<SOAP-ENV:Envelope xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:xsd='http://www.w3.org/2001/XMLSchema'>")
			   .append("<SOAP-ENV:Body>")
			   .append("<VerifyRequest Profile=\"urn:oasis:names:tc:dss:1.0:profiles:XSS\" xmlns=\"urn:oasis:names:tc:dss:1.0:core:schema\" xmlns:urn=\"urn:oasis:names:tc:dss:1.0:profiles:XSS\" xmlns:xd=\"http://www.w3.org/2000/09/xmldsig#\">")
			   .append("<OptionalInputs><urn:ReturnX509CertificateInfo><urn:AttributeDesignator Name=\"urn:catcert:psis:certificateAttributes:KeyOwnerNIF\"/></urn:ReturnX509CertificateInfo></OptionalInputs>")
			   .append("<SignatureObject><Other><xd:X509Data><xd:X509Certificate>").append(new String(Base64.encode(cert)))
			   .append("</xd:X509Certificate></xd:X509Data></Other></SignatureObject>")
			   .append("</VerifyRequest>")
			   .append("</SOAP-ENV:Body></SOAP-ENV:Envelope>");
			
			//http client
			HTTPSender httpClient = new HTTPSender(this.proxySettings);
			
	        //retrieve response body
			InputStream response = httpClient.postMethod(new URL(HOST), xml.toString().getBytes("UTF-8"), "application/xml");
	        
	        if (response != null){

	        	String responseStr = convertStreamToString(response);
	        	System.out.println(responseStr);
	        	//si ens proporcionen el NIF del signatari, obtenim el NIF del certificat de la resposta de PSIS 
	        	if(this.requiredNif!=null && !this.requiredNif.trim().equals("")){
		        	this.psisNif = this.getNif(new ByteArrayInputStream(responseStr.getBytes()));
		        	this.isValidNif = this.compareNifs(this.requiredNif, this.psisNif);
		        	//pintem el resultat per consola
		        	System.out.println("PSIS NIF: "+this.psisNif);
		        	System.out.println("Required NIF: "+this.requiredNif);
		        	System.out.println("Vàlid NIF: "+this.isValidNif);
	        	}
	        		
	        	//reposta de PSIS convertida a String
	        	return responseStr;
	        	
	        }else{
	        	return null;
	        }
		} catch (HTTPSenderException e) {
			e.printStackTrace();
			throw new PSISValidationException("psis.unknown.host");
		} catch (MalformedURLException e) {
			e.printStackTrace();
			throw new PSISValidationException("psis.unknown.host");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw new PSISValidationException("psis.error.other");
		} catch (IOException e) {
			e.printStackTrace();
			throw new PSISValidationException("psis.error.other");
		}
		
	}

	
	/**
	 * Retorna el missatge d'error resultant de la validació de PSIS.
	 * @return
	 */
	public String getError()
	{
		//PSIS KO
		if (this.response.indexOf(AppletConstants.PSIS_RESULTMAJOR_OK) == 0)
		{
			return "psis.process.ko";
		}
		//PSIS OK
		else
		{
			if (this.response.indexOf(AppletConstants.PSIS_RESULTMINOR_EXPIRED) > 0) {
				return "psis.cert.expired";
			}
			else if (this.response.indexOf(AppletConstants.PSIS_RESULTMINOR_REVOKED) > 0) {
				return "psis.cert.revoked";
			}
			else if (this.response.indexOf(AppletConstants.PSIS_RESULTMINOR_UNKNOWN) > 0) {
				return "psis.cert.notpathfound";
			}
			else if (this.response.indexOf(AppletConstants.PSIS_RESULTMINOR_POLICYNOTSUPPORTED) > 0) {
				return "psis.cert.policynotsupported";
			}
			else if(requiredNif!=null && !this.isValidNif){
				return "psis.cert.nif.invalid";
			}
			
			return "";
			
		}
	}
	
	
    /**
     * Obté el NIF de la resposta de PSIS.
     * @param responseIs InputStream de la resposta de PSIS
     */
    private String getNif(InputStream responseIs){

    	try{
    		
	    	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    	DocumentBuilder db = dbf.newDocumentBuilder();
	    	Document doc = db.parse(responseIs);
	    	doc.getDocumentElement().normalize();
	    	
	    	//SOAPEnvelope
	    	Element soapEnv = doc.getDocumentElement();
	    	NodeList nodeList = soapEnv.getChildNodes();
	    	//SOAPBody
	    	Node soapBody = nodeList.item(0);
	    	nodeList = soapBody.getChildNodes();
	    	//VerifyResponse
	    	Node verifyResp = nodeList.item(0);
	    	nodeList = verifyResp.getChildNodes();	    	
	    	for(int i=0;i<nodeList.getLength();i++){
	    		Node child = nodeList.item(i);
	    		String nodeName = removeNameSpace(child.getNodeName());
	    		if(nodeName.equalsIgnoreCase("OptionalOutputs")){
	    			Node optOutsNode = child;
	    			NodeList optOuts = optOutsNode.getChildNodes();
	    			for(int j=0;j<optOuts.getLength();j++){
	    				Node optOut = optOuts.item(j);
	    				String nodeName2 = removeNameSpace(optOut.getNodeName());
	    				if(nodeName2.equalsIgnoreCase("X509CertificateInfo")){
	    					NodeList attrs = optOut.getChildNodes();
	    					for(int k=0;k<attrs.getLength();k++){
	    						Node attr = attrs.item(k);
	    						String nodeName3 = removeNameSpace(attr.getNodeName());
	    						if(nodeName3.equalsIgnoreCase("Attribute")){
	    							NamedNodeMap nnm = attr.getAttributes();
	    							if(nnm!=null){
	    								Node attrNode = nnm.getNamedItem("Name");
	    								String attrName = attrNode.getNodeValue();
	    								if(attrName.equalsIgnoreCase("urn:catcert:psis:certificateAttributes:KeyOwnerNIF")){
	    									NodeList attrValueNode = attr.getChildNodes();
	    									for(int l=0;l<attrValueNode.getLength();l++){
	    										Node attrValue = attrValueNode.item(l);
	    										String nodeName4 = removeNameSpace(attrValue.getNodeName());
	    										if(nodeName4.equalsIgnoreCase("AttributeValue")){
	    											return attrValue.getTextContent();
	    										}
	    									}
	    								}
	    							}
	    						}
	    					}
	    				}
	    			}
	    		}
	    	}
    	
    	}catch(Exception e){
    		e.printStackTrace();
    	}

    	return null;
    }
    
    /**
     * @param qName
     * @return
     */
    private String removeNameSpace(String qName){
		int hasNameSpace =  qName.indexOf(":");
		if(hasNameSpace>0) 
			qName = qName.substring(qName.indexOf(":")+1);
		return qName;
	}
    
    
    /**
     * Compara els valors normalitzats de la parella de NIFs especificars.
     * @param nif1 NIF a comparar
     * @param nif2 NIF a comparar
     * @return
     */
    private boolean compareNifs(String nif1, String nif2){
    	if(nif1!=null && nif2!=null){
	    	//normalitzem les representacions dels NIFs
	    	nif1 = normalizeNif(nif1);
	    	nif2 = normalizeNif(nif2);
	    	//comparació dels valors dels NIFs
	    	if(nif1.equalsIgnoreCase(nif2))
	    		return true;
    	}
   		return false;
    }
    
	/**
	 * Normalització de la representació del NIF.
	 * @param nif NIF a normalitzar
	 * @return valor de la representació del NIF normalitzat
	 */
	private static String normalizeNif(String nif){
	   	char[] psisNifChars = nif.toCharArray();
    	nif = "";
    	for(char ch:psisNifChars){
    		String charr = String.valueOf(ch);
    		if(charr.matches("[012345678TRWAGMYFPDXBNJZSQVHLCKEtrwagmyfpdxbnjzsqvhlcke]")){
    			nif+=charr;
    		}
    	}
    	return nif;
	}
    
    /**
     * @param is
     * @return
     * @throws IOException
     */
    private String convertStreamToString(InputStream is) throws IOException {
        /*
         * To convert the InputStream to String we use the BufferedReader.readLine()
         * method. We iterate until the BufferedReader return null which means
         * there's no more data to read. Each line will appended to a StringBuilder
         * and returned as String.
         */
        if (is != null) {
            StringBuilder sb = new StringBuilder();
            String line;

            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
            } finally {
                is.close();
            }
            return sb.toString();
        } else {        
            return "";
        }
    }
    
    
    
}
