package org.catcert;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;

import lib.org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author oburgos
 *
 */
public class AddBCProvider {
	
	public static void load() throws FileNotFoundException, IOException{
		Security.addProvider(new BouncyCastleProvider());
	}
}
