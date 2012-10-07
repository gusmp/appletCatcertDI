package org.catcert.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * 
 * @author aciffone
 *
 */
public class AppletUtils {

	/**
	 * Transforma un string separat per varis paràmetres en una llista
	 * @param value
	 * @param separator
	 * @return
	 */
	public static List<String> getParams(String value,String separator){
		
		List<String> result = new ArrayList<String>();
		
		StringTokenizer st = new StringTokenizer(value,separator);
		while(st.hasMoreTokens()){
			result.add(st.nextToken());
		}
		
		return result;
		
	}
}
