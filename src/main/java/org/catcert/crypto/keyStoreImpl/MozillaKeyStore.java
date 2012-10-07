package org.catcert.crypto.keyStoreImpl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import org.catcert.crypto.utils.LibsUtils;
import org.catcert.crypto.utils.MozillaProfileUtils;
import org.catcert.crypto.utils.Utils;
import org.catcert.utils.AppletConstants;
import org.catcert.utils.OSName;


/**
 * @author aalcaide
 * @author ciffone
 *
 */
public class MozillaKeyStore {
	
	/**
	 * 
	 * @return KeyStore
	 * @throws MozillaKeyStoreException
	 */
	public static KeyStore loadNSSkeystore() throws MozillaKeyStoreException {		
		
		try {

			//sistema operatiu
	        OSName currentOS = OSName.getOSName();
	        System.out.println("Current OS: "+currentOS);

	        //directori on es guardaran les llibreries en la màquina del client
	        String libsPath = System.getProperty("user.home")+AppletConstants.FILE_SEPARATOR+"CATCert"+AppletConstants.FILE_SEPARATOR;
	        System.out.println("Libraries path: "+libsPath);
			
			//Càrrega de les llibreries de Mozilla:
	        //NSS: Network Security Services
	        //NSPR: Netscape Portable Runtime
	        String[] libsNames = new String[5];
        	String libsInAppletPath = null;
        	String softokn3LibName = null;
        	//Windows
	        if(currentOS.isWindows()){
	        	softokn3LibName = "softokn3.dll";
	        	libsNames[0] = "libnspr4.dll";
	        	libsNames[1] = "libplc4.dll";
	        	libsNames[2] = "libplds4.dll";
	        	libsNames[3] = "softokn3.dll";
	        	libsNames[4] = "freebl3.dll";
	        	//libsNames[5] = "nss3.dll";
	        	//libsNames[6] = "nssckbi.dll";
	        	//libsNames[7] = "smime3.dll";
	        	//libsNames[8] = "ssl3.dll";
	        	libsInAppletPath = "mozilla/windows/";
	        }
	        //Linux
	        else if(currentOS.isLinux()){
	        	softokn3LibName = "libsoftokn3.so";
	        	libsNames[0] = "libnspr4.so";
	        	libsNames[1] = "libplc4.so";
	        	libsNames[2] = "libplds4.so";
	        	libsNames[3] = "libsoftokn3.so";
	        	libsNames[4] = "libfreebl3.so";
	        	//libsNames[5] = "libnss3.so";
	        	//libsNames[6] = "libnssckbi.so";
	        	//libsNames[7] = "libsmime3.so";
	        	//libsNames[8] = "libssl3.so";
		        libsInAppletPath = "mozilla/linux/";
	        } 
	        //Mac OS X
	        else if(currentOS.isMacOSX()){
	        	softokn3LibName = "libsoftokn3.dylib";
	        	libsNames[0] = "libnspr4.dylib";
	        	libsNames[1] = "libplc4.dylib";
	        	libsNames[2] = "libplds4.dylib";
	        	libsNames[3] = "libsoftokn3.dylib";
	        	libsNames[4] = "libfreebl3.dylib";
		        libsInAppletPath = "mozilla/mac/";	        	
	        }else{
	        	//qualsevol altre no està suportat
	        	throw new MozillaKeyStoreException("L'accés al magatzem de Firefox no està suportat pel sistema operatiu "+currentOS+".");
	        }
	        //càrrega de les llibreries
	        LibsUtils.loadLibraries(libsPath, libsInAppletPath, libsNames);

			//Perfil de Firefox:
			//perfil per defecte segons el SO
			String profileDir = MozillaProfileUtils.getFirefoxProfile(currentOS);
			System.out.println("Profile: "+profileDir);

			//Càrrega del keystore
			if(profileDir.equalsIgnoreCase("")){
				throw new MozillaKeyStoreException("No ha sigut possible trobar el directori de Firefox amb el perfil de l'usuari.");
			}
			else{
				//càrrega del keystore
				String conf="name = NSS";
				conf = conf+"\n";
				conf = conf+"attributes= compatibility";
				conf = conf+"\n";
				conf = conf+"slot = 2";
				conf = conf+"\n";
				conf = conf+"library = "+Utils.replaceBackSlashes(libsPath)+softokn3LibName;
				conf = conf+"\n";
				conf = conf+"nssArgs = \"configdir=\'"+profileDir+"\'";
				conf = conf+"\' DbMode ='readOnly' certPrefix=\'\' keyPrefix=\'\' secmod=\'secmod.db\' flags=readOnly\" ";
				
				Provider nss = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(conf.getBytes()));
				
				Security.insertProviderAt(nss, 1);
				
				//BUG de Mozilla: ID = 40826
				//https://issues.apache.org/bugzilla/show_bug.cgi?id=40826
				//KeyStore keyStore = KeyStore.getInstance("PKCS11", nss);
				KeyStore keyStore = KeyStore.getInstance("PKCS11");
				keyStore.load(null, null);
				
				return keyStore;
			}
	        
		} catch (SecurityException e) {
			e.printStackTrace();
			throw new MozillaKeyStoreException(e.getMessage());
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			throw new MozillaKeyStoreException(e.getMessage());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			throw new MozillaKeyStoreException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new MozillaKeyStoreException(e.getMessage());
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new MozillaKeyStoreException(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new MozillaKeyStoreException(e.getMessage());
		}		
	}	
	
}
