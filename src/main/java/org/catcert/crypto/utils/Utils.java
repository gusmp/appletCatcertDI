package org.catcert.crypto.utils;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;

import org.catcert.utils.AppletConstants;

import sun.security.x509.CertificatePoliciesExtension;
import sun.security.x509.PolicyInformation;
import sun.security.x509.X509CertImpl;

//import sun.misc.BASE64Decoder;

/**
 * 
 * @author oburgos
 *
 */
public class Utils {

	public static String tempDirPropertyName = "java.io.tmpdir";
	public static String NOT_FOUND = "NOT_FOUND";

	private static char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	/**
	 * 
	 * @param is
	 * @param off1
	 * @param len1
	 * @param off2
	 * @param len2
	 * @return
	 * @throws IOException
	 */
	public static byte[] readByteRange(byte[] is, int off1, int len1, int off2, int len2) throws IOException {

		byte[] bytes = new byte[len1+len2];		

		System.arraycopy(is, off1, bytes, 0, len1);
		System.arraycopy(is, off2, bytes, len1, len2);

		return bytes;
	}

	/**
	 * 
	 * @param bytes
	 * @return
	 */
	public static InputStream byteArrayToStream(byte[] bytes) {
		return new ByteArrayInputStream(bytes);
	}

	/**
	 * 
	 * @param stream
	 * @return
	 * @throws IOException
	 */
	public static byte[] streamToByteArray(InputStream stream) throws IOException {
		//http://terrencemiao.com/Webmail/msg00944.html
		if (stream == null) {
			return null;
		} else {
			ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
			byte buffer[] = new byte[1024];
			int c = 0;

			while ((c = stream.read(buffer)) > 0) {
				byteArray.write(buffer, 0, c);
			}
			byteArray.flush();
			return byteArray.toByteArray();
		}
	}

	/**
	 * 
	 * @param ba
	 * @return
	 */
	public static String byteArray2Hex(byte[] ba){
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < ba.length; i++){
			int hbits = (ba[i] & 0x000000f0) >> 4;
		int lbits = ba[i] & 0x0000000f;
		sb.append("" + hexChars[hbits] + hexChars[lbits] + " ");
		}
		return sb.toString();
	}

	/**
	 * 
	 * @param path
	 * @return
	 */
	public static InputStream getResource(String path) {
		return Utils.class.getResourceAsStream(path);
	}

	/**
	 * 
	 * @param path
	 * @return
	 */
	public static File getResourceFile(String path) {
		return new File(path);
	}

	/**
	 * 
	 * @param aStartingDir
	 * @return
	 * @throws FileNotFoundException
	 */
	public static List<File> getFileListing(File aStartingDir) throws FileNotFoundException{
		List<File> result = new ArrayList<File>();

		File[] filesAndDirs = aStartingDir.listFiles();
		List<File> filesDirs = Arrays.asList(filesAndDirs);
		Iterator<File> filesIter = filesDirs.iterator();

		File file = null;

		while (filesIter.hasNext()) {
			file = filesIter.next();
			if(file.isDirectory()) {
				//must be a directory
				//recursive call!
				List<File> deeperList = getFileListing(file);
				result.addAll(deeperList);
			}
			else result.add(file);
		}
		Collections.sort(result);
		return result;
	}

	/**
	 * 
	 * @param cert
	 * @param location
	 * @return
	 */
	public static String getCN(X509Certificate cert, String location) {

		String dn = null;

		if (location.equals("subject"))
			dn = cert.getSubjectX500Principal().getName("RFC1779");
		else if (location.equals("issuer"))
			dn = cert.getIssuerX500Principal().getName("RFC1779");
		
		if (dn.equalsIgnoreCase("CN=") == true) {
			return "No CN";
		}

		String dnl = dn.toLowerCase();
		String atr = "cn=";
		int beg = dnl.indexOf(atr);
		if (beg < 0)
			atr="ou=="; //cas FNMT
		int end = dnl.indexOf(',', beg); // No és el cas cn="...",
		if(dn.substring(beg+atr.length(), beg+atr.length()+1).equals("\"")) //cas DNIe cn="..",
			end = dnl.indexOf('"', beg+atr.length()+1);
		if (end >= beg) {
			dn = dn.substring(beg+atr.length(), end);
		}
		else {
			dn = dn.substring(beg+atr.length());
		}
		dn = dn.trim();
		if (dn.startsWith("\"")) dn = dn.substring(1);
		if (dn.endsWith("\"")) dn = dn.substring(0, dn.length()-1);
		return dn;
	}

	/**
	 * 
	 * @param cert
	 * @return
	 * @throws CertificateException 
	 * @throws IOException 
	 */
	public static String[] getCertificatePolicyOIDs(X509Certificate cert) throws CertificateException, IOException {

		CertificatePoliciesExtension polExtension = X509CertImpl.toImpl(cert).getCertificatePoliciesExtension();
		String[] policies = null;
		if(polExtension!=null){
			List<PolicyInformation> certPolicies = (List<PolicyInformation>) polExtension.get(CertificatePoliciesExtension.POLICIES);
		
			policies = new String[certPolicies.size()];

			for(int i = 0; i< certPolicies.size(); i++)
				policies[i] = ((PolicyInformation)certPolicies.get(i)).getPolicyIdentifier().getIdentifier().toString();
		}
		return policies;
	}

	/**
	 * 
	 * @return
	 */
	public static String getCurrentDate() {
		//Format 2006-04-12T11:51:36.977Z
		Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		// Calendar cal = Calendar.getInstance();
		StringBuffer date = new StringBuffer(new Integer(cal.get(Calendar.YEAR)).toString());
		int month = cal.get(Calendar.MONTH)+1;
		date.append("-" + setLength(month, 2));
		date.append("-" + setLength(cal.get(Calendar.DATE), 2));
		date.append("T" + setLength(cal.get(Calendar.HOUR_OF_DAY), 2));
		date.append(":" + setLength(cal.get(Calendar.MINUTE), 2));
		date.append(":" + setLength(cal.get(Calendar.SECOND), 2));
		date.append("." + setLength(cal.get(Calendar.MILLISECOND), 3) + "Z");
		// Format 2007-10-6T11:40:7+01:00
		/*int timezone = (cal.get(Calendar.ZONE_OFFSET) + cal.get(Calendar.DST_OFFSET)) / (60 * 60 * 1000);
		if (timezone == 0)
			date.append("Z");
		else if (timezone < 0) {
			date.append("-");
			timezone = -timezone;
		}
		else
			date.append("+");

		if (timezone != 0) {
			date.append(setLength(timezone, 2)).append(":");
			int zone = Math.abs((cal.get(Calendar.ZONE_OFFSET) + cal.get(Calendar.DST_OFFSET)) / (60 * 1000)) - (timezone * 60);
			date.append(setLength(zone, 2));
		}*/
		return date.toString();
	}

	/**
	 * Adds a number of leading zeros to a given <CODE>String</CODE> in order to get a <CODE>String</CODE>
	 * of a certain length.
	 *
	 * @param		i   		a given number
	 * @param		length		the length of the resulting <CODE>String</CODE>
	 * @return		the resulting <CODE>String</CODE>
	 */
	public static String setLength(int i, int length) {
		StringBuffer tmp = new StringBuffer();
		tmp.append(i);
		while (tmp.length() < length) {
			tmp.insert(0, "0");
		}
		tmp.setLength(length);
		return tmp.toString();
	}

	/**
	 * 
	 * @param CN
	 * @return
	 * @throws IOException 
	 */
	public static byte[] getKnownIssuerNameDigest(String CN) throws IOException {
		byte[] digestBytes = null;

		if(CN.equalsIgnoreCase("EC-IDCat"))
			//digestBytes = new BASE64Decoder().decodeBuffer("Z31jQf/eBy6i1BGffU857Dtm/Cs=");
			digestBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary("Z31jQf/eBy6i1BGffU857Dtm/Cs=");
		else if (CN.equalsIgnoreCase("PREPRODUCCIO EC-SAFP"))
			//digestBytes = new BASE64Decoder().decodeBuffer("jMBsqjDWAviBH4ZWpdFQJvdvswI=");
			digestBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary("jMBsqjDWAviBH4ZWpdFQJvdvswI=");
		else if (CN.equalsIgnoreCase("EC-AL"))
			;
		else if (CN.equalsIgnoreCase("EC-SAFP"))
			;
		else if (CN.equalsIgnoreCase("EC-UR"))
			;
		else if (CN.equalsIgnoreCase("EC-URV"))
			;
		else if (CN.equalsIgnoreCase("EC-PARLAMENT"))
			;
		return digestBytes;
	}

	public static byte[] getKnownIssuerPublicKeyDigest(String CN) throws IOException {
		byte[] digestBytes = null;

		if(CN.equalsIgnoreCase("EC-IDCat"))
			//digestBytes = new BASE64Decoder().decodeBuffer("zZLARUY0dg3S9FuidB2rz2y2C7k=");
			digestBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary("zZLARUY0dg3S9FuidB2rz2y2C7k=");
		else if (CN.equalsIgnoreCase("PREPRODUCCIO EC-SAFP"))
			//digestBytes = new BASE64Decoder().decodeBuffer("YQ6Xhbl929gFQbeN4jATXq5XcN4=");
			digestBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary("YQ6Xhbl929gFQbeN4jATXq5XcN4=");
		else if (CN.equalsIgnoreCase("EC-AL"))
			;
		else if (CN.equalsIgnoreCase("EC-UR"))
			;
		else if (CN.equalsIgnoreCase("EC-URV"))
			;
		else if (CN.equalsIgnoreCase("EC-PARLAMENT"))
			;
		return digestBytes;
	}

	/**
	 * 
	 * @param src
	 * @param dest
	 * @param bufferSize
	 * @throws IOException
	 */
	public static void copyToTempPath(byte[] src, String filename, int bufferSize) throws IOException{
		if(bufferSize<=0){
			bufferSize = 2000; //default bytebuffer
		}

		String tempPath = System.getProperty(tempDirPropertyName, NOT_FOUND);
		if(tempPath.equals(NOT_FOUND)){
			throw new IOException("Temporary File not found");
		}

		InputStream is = byteArrayToStream(src);
		OutputStream os = new BufferedOutputStream(new FileOutputStream(tempPath+System.getProperty("file.separator")+filename+".crl"));
		byte[] buffer = new byte[bufferSize];
		int c;
		while((c = is.read(buffer))!= -1){
			os.write(buffer, 0, c);
		}
		is.close();
		os.close();
		return;
	}

	/**
	 * 
	 * @param filename
	 * @return
	 */
	public static InputStream readTempFile(String filename) throws IOException, FileNotFoundException{
		String tempPath = System.getProperty(tempDirPropertyName, NOT_FOUND);
		if(tempPath.equals(NOT_FOUND)){
			throw new IOException("Temporary File not found");
		}

		InputStream tmpFile = new FileInputStream(tempPath+System.getProperty("file.separator")+filename+".crl");

		return tmpFile;
	}
	
    /**
     * Obtenció del byte array a partir d'un InputStream.
     * @param is InputStream
     * @return byte[]
     * @throws IOException
     */
    public static byte[] getBytes(InputStream is) throws IOException {
    
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	
    	int bytee;
    	while (-1!=(bytee=is.read()))
    	{
    	   baos.write(bytee);
    	}
    	baos.close();
    	byte[] bytes = baos.toByteArray();

        is.close();
        return bytes;
    }
	
    /**
     * Substitueix la contrabarra '\' per la barra '/'.
     * @param str String on fer les substitucions
     * @return String amb les contrabarres substituides per barres
     */
    public static String replaceBackSlashes(String str){
    	return str.replace(AppletConstants.ANTISLASH, AppletConstants.SLASH);
    }
    
    /**
     * Transform a byte[] to a String in base 64. This function is sun.misc.BASE64Encoder compilant
     * @param data data to transform
     * @return String in base 64 and spaced with 76 byte length chunks 
     */
    public static String printBase64Binary(byte[] data)
	{
		String res = javax.xml.bind.DatatypeConverter.printBase64Binary(data);
		String arrData[] = res.split("(?<=\\G.{76})");
		res = "";
		int indexEnd = arrData.length-1;
		for(int i=0; i <= indexEnd; i++)
		{
			res += arrData[i];
			
			if (i != indexEnd)
			{
				res += "\r\n";
			}
		}
		return(res);
	}
}