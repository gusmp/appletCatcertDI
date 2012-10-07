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

import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.NativeUnicodeString;
import be.cardon.nativecall.cryptoapi.Constants;
import be.cardon.nativecall.cryptoapi.CryptoAPICalls;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;

/**High level class for the CryptoAPI HCERTSTORE certificate store handle.
 * @author Rodolphe
 */
public class CAPIStore implements Iterable<CAPICertificate>{
    
    int address;
    
    /**
     * Creates a new instance of CAPIStore, with the given CryptoAPI HCERTSTORE store handle.
     */
    public CAPIStore(int address) {
        this.address = address;
    }
    
    /** Iterates all the certificates in this store.*/
    public Iterator<CAPICertificate> iterator(){
        return new CAPICertificatesIterator(this);
    };
    
   public Iterator<CAPICertificate> iteratorWithPrivateKey(){
        return new CAPICertificatesWithKeyIterator(this);
    };
    
    /** Open a store with the given parameters (see 
     * CryptoAPI documentation in MSDN).
     * TO DO: check that the store exist (now : create an new empty store).
     */
    public static CAPIStore openStore(
            int lpszStoreProvider, 
            int dwMsgAndCertEncodingType,
            int hCryptProv,
            int dwFlags,
            int pvPara)throws CryptoAPIException{
            int storeAddress = new CryptoAPICalls().CertOpenStore(
                    lpszStoreProvider, 
                    dwMsgAndCertEncodingType, 
                    hCryptProv, 
                    dwFlags, 
                    pvPara);
            return new CAPIStore(storeAddress);
    }
    
    /** Opens a store with the given name (CERT_STORE_PROV_SYSTEM and CERT_SYSTEM_STORE_CURRENT_USER.
     * case insensitive (ROOT = root = Root...)
     */
    public static CAPIStore openStore(String storeName) throws CryptoAPIException{
        try{
            Constants CST = new Constants();
            NativeUnicodeString nativeStoreName = NativeUnicodeString.newInstance(storeName);
            return CAPIStore.openStore(
                    CST.CERT_STORE_PROV_SYSTEM, 
                    0, 
                    0,
                    CST.CERT_SYSTEM_STORE_CURRENT_USER,
                    nativeStoreName.getAddress());
        }catch(NativeCallException e){
            throw new CryptoAPIException("NativeCallException", e);
        }
    }
    
    /** Opens the 'My' store.*/
    public static CAPIStore openMyStore() throws CryptoAPIException{
        return CAPIStore.openStore("My");
    }
    
    /** Opens the 'Root' store.*/
     public static CAPIStore openRootStore() throws CryptoAPIException{
        return CAPIStore.openStore("Root");
    }
     
    /** Opens the 'CA' store.*/
    public static CAPIStore openCAStore() throws CryptoAPIException{
        return CAPIStore.openStore("CA");
    }
    
    /** Opens the 'Trust' store.*/
    public static CAPIStore openTrustStore() throws CryptoAPIException{
        return CAPIStore.openStore("Trust");
    }
}
