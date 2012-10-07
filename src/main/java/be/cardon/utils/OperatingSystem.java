/*
Copyright (c) 2006, CARDON DE LICHTBUER Rodolphe
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list 
of conditions and the following disclaimer. 

2. Redistributions in binary form must reproduce the above copyright notice, this 
list of conditions and the following disclaimer in the documentation and/or 
other materials provided with the distribution. 

3. The name of the author or contributors may not be used to endorse or promote 
products derived from this software without specific prior written permission. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
DAMAGE.
 */

package be.cardon.utils;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;

/**Provides OS properties.
 *
 * @author Rodolphe
 */
public class OperatingSystem {
    
    public static final String OS_NAME_PROPERTY = "os.name";
    public static final String USER_HOME_PROPERTY = "user.home";
    public static final String FILE_SEPARATOR_PROPERTY = "file.separator";
    
    
    /**Returns true if the OS is any version of Microsoft Windows.*/
    public static boolean isWindows(){
        String NOTDEFINED = "not defined";
        String WIN = "Windows";
        String osname = System.getProperty(OS_NAME_PROPERTY,NOTDEFINED);
        if(osname==NOTDEFINED){
            System.err.println("System propery 'os.name' is not defined.");
            return false;
        }
        if(osname.contains(WIN)){
            return true;
        }
        return false;
    }
    
    /**Prints all the system properties to the standard output.*/
    public static void printSystemProperties(){
        Properties prop = System.getProperties();
        for(Enumeration keyEnum = prop.keys();keyEnum.hasMoreElements();){
            String keyString = (String)keyEnum.nextElement();
            String propString = prop.getProperty(keyString);
            System.out.println(keyString + "=" + propString);
           
        }
    }
    public static String getSeparator(){
        return System.getProperty(FILE_SEPARATOR_PROPERTY);
    }
    public static boolean isFileCaseSensitive(){
        //no if windows, yes otherwise
        return !isWindows();
    }
    
    /**open the file with the operating system.*/
    public static boolean open(File file){
        try{
        if(!isWindows()){
            return false;
            //not implemented for linux and other OS.  
        }
        String path = file.getAbsolutePath();
        String cmd = "cmd.exe /C \""+path +"\"";
        Debug.println("OperatingSystem: exec: "+cmd);
        Process proc = Runtime.getRuntime().exec(cmd);
        return true;
        }catch(IOException e){
            e.printStackTrace();
            //could not open the file
            return false;
        }
    }    
}
