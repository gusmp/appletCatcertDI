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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

/**
 *
 * @author Rodolphe
 */
public class LibraryLoader {
    
    public static String tempDirPropertyName = "java.io.tmpdir";
    public static String libPathPropertyName = "java.library.path";
    public static String NOT_FOUND = "NOT_FOUND";
    
    /** Creates a new instance of LibraryLoader */
    public LibraryLoader() {
    }

    public static void loadLib(String libName)
    throws IOException, InterruptedException{

        String filename = "/be/cardon/utils/" + libName;        
        URL inputStreamLibURL = LibraryLoader.class.getResource(filename);
        if(inputStreamLibURL==null){
            throw new IOException("Resource not found: " + filename);
        }
        
        String tempPath = System.getProperty(tempDirPropertyName, NOT_FOUND);
        if(tempPath.equals(NOT_FOUND)){
            throw new IOException("Temporary File not found");
        }
        File tempDir = new File(tempPath);
        
        //first try to overwrite the default file
        File defaultFile = new File(tempPath, libName);
        
        boolean useDefaultFile = false;
        if(defaultFile.exists()){
            try{
                useDefaultFile = defaultFile.delete();
                //return false if the library cannot be deleted (locked)
            }catch(Exception e){
                e.printStackTrace();
                useDefaultFile = false;
            }
        }else{
            useDefaultFile = true;
        }
        
        File tempFile;
        if(useDefaultFile){
            tempFile = defaultFile;
        }else{
            tempFile = File.createTempFile(libName, "", tempDir);
        }
        
        LibraryLoader.copy(inputStreamLibURL.openStream() ,tempFile, 0);
        
        Runtime.getRuntime().load(tempFile.getAbsolutePath());
    }
    
    public static void copy(InputStream src, File dest, int bufferSize) throws IOException{
        if(bufferSize<=0){
            bufferSize = 2000; //default bytebuffer
        }
        InputStream is = src;
        OutputStream os = new BufferedOutputStream(new FileOutputStream(dest));
        byte[] buffer = new byte[bufferSize];
        int c;
        while((c = is.read(buffer))!= -1){
            os.write(buffer, 0, c);
        }
        is.close();
        os.close();
        return;
    }
    
    public static void copy(File src, File dest, int bufferSize) throws IOException{
        if(bufferSize<=0){
            bufferSize = 2000; //default bytebuffer
        }
        InputStream is = new BufferedInputStream(new FileInputStream(src));
        OutputStream os = new BufferedOutputStream(new FileOutputStream(dest));
        byte[] buffer = new byte[bufferSize];
        int c;
        while((c = is.read(buffer))!= -1){
            os.write(buffer, 0, c);
        }
        is.close();
        os.close();
        return;
    }
}