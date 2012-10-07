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

import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.cryptoapi.CryptoAPICalls;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;
import be.cardon.nativecall.cryptoapi.StructCERT_CHAIN_CONTEXT;
import be.cardon.nativecall.cryptoapi.StructCERT_CHAIN_ELEMENT;
import be.cardon.nativecall.cryptoapi.StructCERT_CHAIN_PARA;
import be.cardon.nativecall.cryptoapi.StructCERT_ENHKEY_USAGE;
import be.cardon.nativecall.cryptoapi.StructCERT_SIMPLE_CHAIN;
import be.cardon.nativecall.cryptoapi.StructCERT_USAGE_MATCH;


/**Simple certificate chain.
 *
 * @author Rodolphe
 */
public class CAPICertificateChain {
    
    //pointer to the native chain context CERT_CHAIN_CONTEXT
    private StructCERT_CHAIN_CONTEXT _chainContext;
    
    /**Returns the native chain context CERT_CHAIN_CONTEXT structure
     */
    public StructCERT_CHAIN_CONTEXT GetNativeStructChainContext(){
        return _chainContext;
    }
    
    /** Creates a new instance of CAPICertificateChain, using standard chain engine,
     * and without any criterion (see MSDN documentation).*/
    public CAPICertificateChain(CAPICertificate cert) throws CryptoAPIException{
        try{
        //CERT_CHAIN_PARA DEFINITION
        boolean extraFields = false;
        StructCERT_CHAIN_PARA ChainPara = StructCERT_CHAIN_PARA.newInstance(extraFields);
        StructCERT_USAGE_MATCH usageMatch = ChainPara.RequestedUsage();
        usageMatch.dwType().set(be.cardon.nativecall.cryptoapi.Constants.USAGE_MATCH_TYPE_AND);
        StructCERT_ENHKEY_USAGE usage = usageMatch.Usage();
        usage.cUsageIdentifier().set(0);
        usage.rgpszUsageIdentifier().set(0);
        
        int hChainEngine = 0; //default chain engine
        int pCertContext = cert.GetNativeStructCERT_CONTEXT().getAddress();
        int pTime = 0; //current time
        int hAdditionalStore = 0; //no additional store
        int pChainPara = ChainPara.getAddress();
        int dwFlags = 0; //no flags
        
        int pChainContext = new CryptoAPICalls().CertGetCertificateChain(
                hChainEngine, 
                pCertContext, 
                pTime, 
                hAdditionalStore, 
                pChainPara, 
                dwFlags);
        
        this._chainContext = new StructCERT_CHAIN_CONTEXT(pChainContext);
        }catch(NativeCallException e){
            throw new CryptoAPIException("NativeCallException" , e);
        }
    }
   /**returns a first certificate chain. The first certificate is the end certificate, 
    * and the last certificate is the root certificate. Returns null if no certificates
    * are found. 
    */
   public CAPICertificate[] getCertificateChain() throws CryptoAPIException{
       try{
            int numberOfChains = _chainContext.cChain().get();
            if(numberOfChains==0){
                return null;
            }
            //choose the first chain.
            int index = 0;
            StructCERT_SIMPLE_CHAIN[] chains = _chainContext.Chain();
            //StructCERT_SIMPLE_CHAIN chain = _chainContext.Chain().getElement(index);
            StructCERT_SIMPLE_CHAIN chain = chains[0];
            
            //to do : check status

            //retrieves the certificates
            StructCERT_CHAIN_ELEMENT[] chainElementArray = chain.element();
            int numberOfCertificates = chainElementArray.length;
            CAPICertificate[] certs = new CAPICertificate[numberOfCertificates];
            for(int it=0 ; it<numberOfCertificates ; it++){
                certs[it] = new CAPICertificate(chainElementArray[it].certContext());
            }            
            return certs;
            
       }catch(NativeCallException e){
           throw new CryptoAPIException("NativeCallException", e);
       }
   }
   
   public void finalize() throws Throwable{
        new CryptoAPICalls().CertFreeCertificateChain(this._chainContext.getAddress());
        super.finalize();
    }
    
}
