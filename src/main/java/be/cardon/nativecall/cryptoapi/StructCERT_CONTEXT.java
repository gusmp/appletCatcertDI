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


/**Wrapper for structure {@code CERT_CONTEXT}.
 * @author CARDON DE LICHTBUER Rodolphe 
 */
public class StructCERT_CONTEXT extends NativeStructure{
    
    /*typedef struct _CERT_CONTEXT {  
     4 DWORD dwCertEncodingType;  [0]   
     4 BYTE* pbCertEncoded;   [4]
     4 DWORD cbCertEncoded;   [8]
     4 PCERT_INFO pCertInfo;  [12]
     4 HCERTSTORE hCertStore; [16]
    } CERT_CONTEXT, *PCERT_CONTEXT;
    typedef const CERT_CONTEXT *PCCERT_CONTEXT;
*/
    
    public static final Integer[] elementsSize  = {4, 4, 4, 4, 4};
    public static final int lengthInBytes = 20;
    private static java.util.List<Integer> relAddresses = new java.util.ArrayList<Integer>();

    /** Creates a new instance of the structure, new native structure. */
    public StructCERT_CONTEXT() throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses);
    }
    
    /** Creates a new instance of the structure, existing native structure. */
    public StructCERT_CONTEXT(int address) throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses, address);
    }
 
    /******************** MEMBERS FUNCTIONS*******************/
    
    /**Returns the CryptoAPI certificate encoding type.*/
    public NativeInt dwCertEncodingType()throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(0));
    }
    
    /**Returns the address of the encoded certificate. pbCertEncoded 
     * gives the size in bytes. Please use the higher level function CertEncoded().*/
    public NativeInt pbCertEncoded()throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(1));
    }
    
    /**Returns the size (in bytes) of the encoded certificate at address 
     * pbCertEncoded. Please use the higher level function CertEncoded().*/
    public NativeInt cbCertEncoded()throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(2));
    }
    
    /**Returns the address of the native structure CERT_INFO of this 
     * certificate. Please use the higher level function 
     * {@link #CertInfo CertInfo}. */
    public NativeInt pCertInfo()throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(3));
    }
    
    /**Returns the handle of the certificate store*/
    public NativeInt hCertStore()throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(4));
    }
    
    
    /******************** EXTENDED FUNCTIONS*******************/
    
    /** Returns the encoded certificate.*/
    public byte[] CertEncoded()throws NativeCallException{
        return LLC.readBytes(
                this.pbCertEncoded().get(), 
                this.cbCertEncoded().get());
    }

   /**Returns the StructCERT_INFO wrapper object associated with the CERT_INFO 
     * structure of this certificate.*/
    public StructCERT_INFO CertInfo() throws NativeCallException{
        return new StructCERT_INFO(this.pCertInfo().get());
    }
}
