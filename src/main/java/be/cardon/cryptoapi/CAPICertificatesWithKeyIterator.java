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

package be.cardon.cryptoapi;

import java.util.Iterator;
import java.util.NoSuchElementException;

import be.cardon.nativecall.LastError;
import be.cardon.nativecall.cryptoapi.CryptoAPICalls;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;

/**Iterates the certificates from a store.
 * @author CARDON DE LICHTBUER Rodolphe 
 */
public class CAPICertificatesWithKeyIterator implements Iterator<CAPICertificate> {
    
    CAPIStore store;
    int DuplicatedCertAddress; 
    int EnumCertAddress;
            
    /**
     * Creates a new instance of CAPICertificatesIterator. 
     */
    public CAPICertificatesWithKeyIterator(CAPIStore store){
        this.store = store;
        try{
            this.EnumCertAddress = 0;
            do{
               EnumCertAddress = new CryptoAPICalls().CertEnumCertificatesInStore(store.address, EnumCertAddress);
            }while(!hasPrivateKeyOrNull(this.EnumCertAddress));
        }catch(CryptoAPIException e){
            e.printStackTrace();
            this.EnumCertAddress = 0;
        }
    }
    
    private boolean hasPrivateKeyOrNull(int CertificateAddress) throws CryptoAPIException{
        if(CertificateAddress==0){
            return true; //end of loop
        }else{
            return new CAPICertificate(CertificateAddress).hasPrivateKey();
        }
    }
    /** Returns TRUE if there is a next certificate.*/
    public boolean hasNext(){
        
        if(EnumCertAddress==0){
            return false;
        }else{
            return true;
        }
    }
    /** Returns the next certificate.*/
    public CAPICertificate next() throws NoSuchElementException {
        try{
            CryptoAPICalls CAPI = new CryptoAPICalls();
            int DuplicatedCertAddress = CAPI.CertDuplicateCertificateContext(EnumCertAddress);
            do{
            EnumCertAddress = new CryptoAPICalls().CertEnumCertificatesInStore(store.address, EnumCertAddress);
            }while(!hasPrivateKeyOrNull(this.EnumCertAddress));
            return new CAPICertificate(DuplicatedCertAddress);
            
        }catch(Exception e){
            System.err.println("ERROR with CertificatesIterator:");
            System.err.println("Win Last error = "+LastError.getLastError());
            e.printStackTrace();
            return null;
        }
    }
    /** NOT ALLOWED, throws UnsupportedOperationException.¨*/
    public void remove() throws UnsupportedOperationException{
        throw new UnsupportedOperationException();
    }
}
