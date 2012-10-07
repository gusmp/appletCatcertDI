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

import be.cardon.nativecall.NativeByteArray;
import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.NativeInt;
import be.cardon.nativecall.NativeStructure;

/**Wrapper for structure {@code CERT_INFO}.
 * 
 * @author Rodolphe
 */
public class StructCERT_INFO extends NativeStructure{
    /*
    112 typedef struct _CERT_INFO {  
      4 DWORD dwVersion;  
      8 CRYPT_INTEGER_BLOB SerialNumber;  
     12 CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;  
      8 CERT_NAME_BLOB Issuer;  
      8 FILETIME NotBefore;  
      8 FILETIME NotAfter;  
      8 CERT_NAME_BLOB Subject;  
     24 CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;  
     12 CRYPT_BIT_BLOB IssuerUniqueId;  
     12 CRYPT_BIT_BLOB SubjectUniqueId;  
      4 DWORD cExtension;  
      4 PCERT_EXTENSION rgExtension;
       } CERT_INFO, *PCERT_INFO;
     */
    
    
    public static final Integer[] elementsSize  = {4, 8, 12, 8, 8, 8, 8, 24, 12, 12, 4, 4};
    public static final int lengthInBytes = 112;
    private static java.util.List<Integer> relAddresses = new java.util.ArrayList<Integer>();

    /** Creates a new instance of the structure, new native structure. */
    public StructCERT_INFO() throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses);
    }
    
    /** Creates a new instance of the structure, existing native structure. */
    public StructCERT_INFO(int address) throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses, address);
    }

    /******************** MEMBERS FUNCTIONS*******************/
    
    public NativeInt dwVersion()throws NativeCallException{
        return NativeInt.newInstance(
                this.getNativeObjectElement(0));
    }

    public StructCRYPT_INTEGER_BLOB SerialNumber() throws NativeCallException{
        return new StructCRYPT_INTEGER_BLOB(
                this.getAddressOfElement(1));
    }
    
    public NativeByteArray SignatureAlgorithm()throws NativeCallException{
        return NativeByteArray.newInstance(
                this.getNativeObjectElement(2));
    }

    public StructCERT_NAME_BLOB Issuer() throws NativeCallException{
        return new StructCERT_NAME_BLOB(
                this.getAddressOfElement(3));
    }
    
    public NativeByteArray NotBefore()throws NativeCallException{
        return NativeByteArray.newInstance(
                this.getNativeObjectElement(4));
    }
    
    public NativeByteArray NotAfter()throws NativeCallException{
        return NativeByteArray.newInstance(
                this.getNativeObjectElement(5));
    }
    
    public StructCERT_NAME_BLOB Subject() throws NativeCallException{
        return new StructCERT_NAME_BLOB(
                this.getAddressOfElement(6));
    }

    public NativeByteArray SubjectPublicKeyInfo()throws NativeCallException{
        return NativeByteArray.newInstance(
                this.getNativeObjectElement(7));
    }
     
    public NativeByteArray IssuerUniqueId()throws NativeCallException{
        return NativeByteArray.newInstance(
                this.getNativeObjectElement(8));
    }
    
    public NativeByteArray SubjectUniqueId()throws NativeCallException{
        return NativeByteArray.newInstance(
                this.getNativeObjectElement(9));
    }

    public NativeInt cExtension()throws NativeCallException{
        return NativeInt.newInstance(
                this.getNativeObjectElement(10));         
    }
    
    public NativeByteArray rgExtension()throws NativeCallException{
        return NativeByteArray.newInstance(
                this.getNativeObjectElement(11));
    }
}
    
    