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

import java.io.PrintStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;


/**To dump object to a write stream
 *
 * @author Rodolphe
 */
public class Dumper {
    
    /** Creates a new instance of Dumper */
    public Dumper() {
    }
    
    /**Dump the chain of certificate (n� + subject name).*/
    public static void dumpChain(Certificate[] certs, PrintStream printStream){
        int nbOfCerts = certs.length;
        for(int count=0;count<nbOfCerts;count++){
            printStream.println("["+count+"] : "+((X509Certificate)certs[count]).getSubjectX500Principal());
        }
    }
    
    
    
}
