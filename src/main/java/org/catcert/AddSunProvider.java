package org.catcert;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;

import sun.security.provider.Sun;

/**
 * 
 * @author oburgos
 *
 */
public class AddSunProvider {
	
	/**
	 * 
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public static void load() throws FileNotFoundException, IOException{
		Security.addProvider(new Sun());
	}
}
