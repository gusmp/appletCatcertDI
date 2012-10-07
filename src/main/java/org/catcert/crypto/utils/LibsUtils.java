package org.catcert.crypto.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.catcert.AppletSignatura;
import org.catcert.crypto.keyStoreImpl.MozillaKeyStoreException;

public class LibsUtils {

	
	
	/**
	 * Càrrega de les llibreries de Mozilla a la màquina del client:
	 * <br/>NSPR -> Netscape Portable Runtime 
	 * <br/>NSS -> Network Security Services
	 * @param libsPath path on s'han de copiar les llibreries a la màquina del client
	 * @param libsInAppletPath path de les llibreries dins el classpath de l'applet
	 * @param libsNames noms de les llibreries a carregar
	 * @throws MozillaKeyStoreException
	 * @throws IOException
	 */
	public static void loadLibraries(String libsPath, String libsInAppletPath, String[] libsNames) throws MozillaKeyStoreException, IOException{
		File libFile = new File(libsPath);
		libFile.mkdir();
		for(String libName:libsNames){
			loadLibrary(libsPath, libsInAppletPath, libName);
		}
	}
	
	
	/**
	 * Còpia de la llibreria especificada en la màquina del client (si no existeix prèviament), i càrrega d'aquesta al sistema.
	 * @param libsPath path on s'han de copiar les llibreries a la màquina del client
	 * @param libsInAppletPath path de les llibreries dins el classpath de l'applet
	 * @param libName llibreria a carregar
	 * @throws IOException
	 */
	private static void loadLibrary(String libsPath, String libsInAppletPath, String libName) throws IOException{
		//copiem la llibreria a la màquina del client
		String libAppletPath = libsInAppletPath+libName;
		String libClientPath = libsPath+libName;
		File libFile = new File(libClientPath);
		copyLibraryToPath(libFile, libAppletPath, libClientPath);
		//càrrega de la llibreria al sistema
		System.load(libClientPath);
	}
	
	
	/**
	 * Càrrega d'una llibreria, des de l'applet a l'ordinador del client.
	 * @param libFile llibreria a carregar
	 * @param libInAppletClassPath path de la llibreria dins el classpath de l'applet
	 * @param libInClientPath path on s'ha de copiar la llibreria a la màquina del client
	 * @throws IOException
	 */
	private static void copyLibraryToPath(File libFile, String libInAppletClassPath, String libInClientPath) throws IOException{
		
		//System.out.println("Library in applet path: "+libInAppletClassPath);
		//System.out.println("Library in client path: "+libInClientPath);
		
		boolean fileCreated = libFile.createNewFile();
		if(fileCreated){
			InputStream is = null;
			FileOutputStream fos = null;
			try{
				ClassLoader cl = AppletSignatura.class.getClassLoader();
				is = cl.getResourceAsStream(libInAppletClassPath);
				byte[] data = Utils.getBytes(is);
				fos = new FileOutputStream(libInClientPath,false);
				fos.write(data);
			}finally{
				if(fos != null) fos.close();
				if(is != null) is.close();				
			}
		}
	}
	
}
