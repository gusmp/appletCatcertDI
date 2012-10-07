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

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import be.cardon.nativecall.LastError;
import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.cryptoapi.Constants;
import be.cardon.nativecall.cryptoapi.CryptoAPICalls;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;
import be.cardon.nativecall.cryptoapi.StructCERT_CONTEXT;
import be.cardon.nativecall.cryptoapi.StructCERT_INFO;
import be.cardon.nativecall.cryptoapi.StructCERT_NAME_BLOB;
import be.cardon.nativecall.cryptoapi.StructCRYPT_INTEGER_BLOB;
import be.cardon.utils.ByteArrayTools;
import be.cardon.utils.HexUtils;


/**High level class for the CERT_CONTEXT CryptoAPI structure
 *
 * @author Rodolphe
 */
public class CAPICertificate {
    
    private StructCERT_CONTEXT certContext;
    private Certificate cert = null; // java.security.cert.Certificate object
    
    /**
     * Creates a new instance of CAPICertificate with the given CERT_CONTEXT structure 
     * address. 
     */
    public CAPICertificate(StructCERT_CONTEXT certContext){
        this.certContext = certContext;
    }

    public CAPICertificate(int address) throws CryptoAPIException{
        try{
        certContext = new StructCERT_CONTEXT(address);
        }catch(NativeCallException e){
            throw new CryptoAPIException(e.getMessage());
        }
    }
    
    /**
     * Creates a new instance of CAPICertificate, allocates memory for a CERT_CONTEXT
     *     structure. 
     */
    public CAPICertificate() throws CryptoAPIException{
        try{
        certContext = new StructCERT_CONTEXT();
        }catch(NativeCallException e){
            throw new CryptoAPIException(e.getMessage());
        }
    }
    
    /** Returns the wrapper for the CERT_CONTEXT structure.*/
    public StructCERT_CONTEXT GetNativeStructCERT_CONTEXT(){
        return certContext;
    }
    
   /** Returns TRUE if the certificate has a CERT_KEY_PROV_INFO_PROP_ID property
    * or a CERT_KEY_CONTEXT_PROP_ID property.*/ 
   public boolean hasPrivateKey() throws CryptoAPIException{
      if(this.hasProperty(Constants.CERT_KEY_PROV_INFO_PROP_ID) | 
         this.hasProperty(Constants.CERT_KEY_CONTEXT_PROP_ID)){
          return true;
       }else{
          return false;
       }
   }
   
   /**return the Private Key
          * <p>WARNING !</p>
     * <p><b>The password should be null</b>. This is the default case. The CSP (cryptographic
     * service provider) will display a window (PIN, or other) to the user if needed.</p>
     * <p>You can also give a password (PIN) programatically. The CSP <b>MUST</b> support the function CryptoAPI
     * function CryptSetProvParam with PP_SIGNATURE_PIN or PP_KEYEXCHANGE_PIN. 
     * Most CSP like the Microsoft Basic CSP or the Belgian eid middleware doesn't support this 
     * function. The CSP from 'Nexus Personal' has been tested with that. All CSP supporting 
     * Smard Card Windows logon should support this function.</p>.
     *<p><b>The password doesn't support Unicode (CryptoAPI use byte[], not char[]). In the
     * future, we will create a property to choose the encoding for password.</b></p>
     *@throws CryptoAPIException if the CryptSetProvParam function is not supported
     *for PIN (PINNotSupportedException), or other error.
    */
   public CAPIPrivateKey getPrivateKey(char[] password) throws CryptoAPIException{
       return getPrivateKey(0, password);
   }
   
   /** return the Private Key, dwFlags for CryptAcquireCertificatePrivateKey 
    * function
              * <p>WARNING !</p>
     * <p><b>The password should be null</b>. This is the default case. The CSP (cryptographic
     * service provider) will display a window (PIN, or other) to the user if needed.</p>
     * <p>You can also give a password (PIN) programatically. The CSP <b>MUST</b> support the function CryptoAPI
     * function CryptSetProvParam with PP_SIGNATURE_PIN or PP_KEYEXCHANGE_PIN. 
     * Most CSP like the Microsoft Basic CSP or the Belgian eid middleware doesn't support this 
     * function. The CSP from 'Nexus Personal' has been tested with that. All CSP supporting 
     * Smard Card Windows logon should support this function.</p>.
     *<p><b>The password doesn't support Unicode (CryptoAPI use byte[], not char[]). In the
     * future, we will create a property to choose the encoding for password.</b></p>
     *@throws CryptoAPIException if the CryptSetProvParam function is not supported
     *for PIN (PINNotSupportedException), or other error.
    */
   public CAPIPrivateKey getPrivateKey(int dwFlags, char[] password) 
   throws CryptoAPIException{
       if(!hasPrivateKey()){
           throw new CryptoAPIException("This certificate has no private key");
       }else{
           return new CAPIPrivateKey(this, dwFlags, password);
       }
   }
       
   /** Returns TRUE if the certificate has the given extended property.*/
   private boolean hasProperty(int Property) throws CryptoAPIException{
       try{
          (new CryptoAPICalls()).CertGetCertificateContextProperty(certContext.getAddress(),Property);
       }catch(CryptoAPIException e){
             if (LastError.getLastError()==-2146885628) //CRYPT_E_NOT_FOUND (winerror.h)
             {
                 return false;
             }
             else{
                 throw e;
             }
       }
       return true;
   }
   
   /** Returns the Issuer RDN in X500 format.*/
   public String getIssuerRDN() throws CryptoAPIException{
       try{
       StructCERT_INFO info = this.certContext.CertInfo();
       StructCERT_NAME_BLOB issuername = info.Issuer();
       String issuerString = new CryptoAPICalls().CertNameToStrW(
                this.certContext.dwCertEncodingType().get(), 
                issuername.getAddress(),
                Constants.CERT_X500_NAME_STR);
       //String issuerString = "empty";
       return issuerString;
       }catch(NativeCallException e){
           throw new CryptoAPIException(e.getMessage());
       }
   }
   
   /** Returns the issuer serial number in hexadecimal (without spaces).*/
   public String getIssuerSerialNumber()  throws CryptoAPIException{
       try{
       StructCERT_INFO info = this.certContext.CertInfo();
       StructCRYPT_INTEGER_BLOB issuernumber = info.SerialNumber();
       byte[] issuerSNBytes = issuernumber.data().read();
       String issuerSNString = 
                HexUtils.ByteArray2Hex(ByteArrayTools.reverseByteArray(issuerSNBytes));
       return issuerSNString;
       }catch(NativeCallException e){
           throw new CryptoAPIException("NativeCallException", e);
       }
   }   
    
   /** Returns the encoded certificate (format ?).*/
    public byte[] CertEncoded() throws CryptoAPIException{
        try{
            return certContext.CertEncoded();
       }catch(NativeCallException e){
           throw new CryptoAPIException("NativeCallException", e);
       }
        
    }

    /** Returns the java.security.cert.Certificate object (uses the default X.509 CertificateFactory) */
    public Certificate getCertificate() throws CertificateException,CryptoAPIException{
        try{
            if(cert==null){
                   CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                   cert = certFactory.generateCertificate(new ByteArrayInputStream(certContext.CertEncoded()));
                   return cert;
            }else{
                return cert;
            }
       }catch(NativeCallException e){
           throw new CryptoAPIException("NativeCallException", e);
       }
    }
    
    /** Returns the java.security.cert.X09Certificate object (converts getCertificate() ) */
    public X509Certificate getX509Certificate() throws CertificateException, CryptoAPIException{
       return (X509Certificate)this.getCertificate();
    }
}