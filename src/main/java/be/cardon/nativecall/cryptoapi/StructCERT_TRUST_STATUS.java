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

package be.cardon.nativecall.cryptoapi;

import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.NativeInt;
import be.cardon.nativecall.NativeStructure;


/**Wrapper for structure {@code CERT_TRUST_STATUS}.
 * 
 * @author Rodolphe
 *<pre>
 *typedef struct _CERT_TRUST_STATUS {  
 * DWORD dwErrorStatus;  
 * DWORD dwInfoStatus;
} CERT_TRUST_STATUS, *PCERT_TRUST_STATUS;
 *</pre>
 */
public class StructCERT_TRUST_STATUS extends NativeStructure{
    
    public final static Integer[] elementsSize  = {4,4};
    public final static int lengthInBytes = 8;
    private static java.util.List<Integer> relAddresses = 
            new java.util.ArrayList<Integer>();

    /** Creates a new instance of the structure, new native structure. */
    public StructCERT_TRUST_STATUS() throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses);
    }
    
    /** Creates a new instance of the structure, existing native structure. */
    public StructCERT_TRUST_STATUS(int address) throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses, address);
    }


    /******************** MEMBERS FUNCTIONS*******************/
    
    public NativeInt dwErrorStatus()throws NativeCallException{
        return NativeInt.newInstance(
                this.getNativeObjectElement(0));
    }
    
    public NativeInt dwInfoStatus()throws NativeCallException{
        return NativeInt.newInstance(
                this.getNativeObjectElement(1));
    }

    /******************** EXTENDED FUNCTIONS*******************/
    
}
    