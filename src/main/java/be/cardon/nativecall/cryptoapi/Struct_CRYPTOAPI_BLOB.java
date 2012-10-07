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

     * 8 typedef struct _CRYPTOAPI_BLOB 
        {  
        4 DWORD cbData;  
        4 BYTE* pbData;
        } 
        CRYPT_INTEGER_BLOB, 
        *PCRYPT_INTEGER_BLOB, 
        CRYPT_UINT_BLOB, 
        *PCRYPT_UINT_BLOB, 
        CRYPT_OBJID_BLOB, 
        *PCRYPT_OBJID_BLOB, 
        CERT_NAME_BLOB, 
        *PCERT_NAME_BLOB, 
        CERT_RDN_VALUE_BLOB, 
        *PCERT_RDN_VALUE_BLOB, 
        CERT_BLOB,
        *PCERT_BLOB, 
        CRL_BLOB, 
        *PCRL_BLOB, 
        DATA_BLOB, 
        *PDATA_BLOB, 
        CRYPT_DATA_BLOB, 
        *PCRYPT_DATA_BLOB, 
        CRYPT_HASH_BLOB, 
        *PCRYPT_HASH_BLOB, 
        CRYPT_DIGEST_BLOB, 
        *PCRYPT_DIGEST_BLOB, 
        CRYPT_DER_BLOB, 
        *PCRYPT_DER_BLOB, 
        CRYPT_ATTR_BLOB, 
        *PCRYPT_ATTR_BLOB;
     */
/*
 * Struct_CRYPTOAPI_BLOB.java
 *
 * Created on 9 août 2006, 17:44
 */

package be.cardon.nativecall.cryptoapi;

import be.cardon.nativecall.NativeByteArray;
import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.NativeInt;
import be.cardon.nativecall.NativeStructure;


/**Wrapper for structure {@code _CRYPTOAPI_BLOB}.
 *
 * @author Rodolphe
 */
public class Struct_CRYPTOAPI_BLOB extends NativeStructure{
    
    
    private static Integer[] elementsSize  = {4, 4};
    private static int lengthInBytes = 8;
    private static java.util.List<Integer> relAddresses = new java.util.ArrayList<Integer>();

    /** Creates a new instance of the structure, new native structure. */
    public Struct_CRYPTOAPI_BLOB() throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses);
    }
    
    /** Creates a new instance of the structure, existing native structure. */
    public Struct_CRYPTOAPI_BLOB(int address) throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses, address);
    }


    /******************** MEMBERS FUNCTIONS*******************/
    
    public NativeInt cbData() throws NativeCallException{
        return NativeInt.newInstance(
                this.getNativeObjectElement(0));
    }

    public NativeInt pbData() throws NativeCallException{
        return NativeInt.newInstance(
                this.getNativeObjectElement(1));
    }
    
    
    /******************** EXTENDED FUNCTIONS*******************/
    public NativeByteArray data()  throws NativeCallException{
        return new NativeByteArray(
                this.cbData().get(),
                this.pbData().get());
    }
    

}
