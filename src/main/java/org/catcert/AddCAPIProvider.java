package org.catcert;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;

import be.cardon.cryptoapi.provider.CryptoAPIProvider;

/**
 * 
 * @author oburgos
 *
 */
public class AddCAPIProvider {
	
	/**
	 * 
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public static void load() throws FileNotFoundException, IOException{		
		Security.addProvider(new CryptoAPIProvider());
	}
}
