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

package be.cardon.cryptoapi.provider;

import java.security.PrivateKey;
import java.security.cert.CertificateException;

import be.cardon.cryptoapi.CAPICertificate;
import be.cardon.cryptoapi.CAPIPrivateKey;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;
/**CrypoAPI Private Key
 *
 * @author Rodolphe
 */
public class CryptoAPIPrivateKey implements PrivateKey {
    
    /** Constant String to indentify a cryptoAPI Key.*/
    public static String CryptoAPIKeyFormat = "CAPIKey";
    
    private CAPIPrivateKey CAPIprivKey;
    private String alg;
    
    /** Creates a new instance of CryptoAPIPrivateKey 
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
    public CryptoAPIPrivateKey(CAPICertificate CAPIcert, char[] password) throws CryptoAPIException {
        this.CAPIprivKey = CAPIcert.getPrivateKey(password);
        try{
        this.alg = CAPIcert.getCertificate().getPublicKey().getAlgorithm(); // "RSA" or "DSA"
        }catch(CertificateException e){
            throw new CryptoAPIException("CertificateException :"+e.getMessage());
        }
    }
    
    /**Returns the standard algorithm name for this key.*/
    public String getAlgorithm() {
        return alg;
    }
    
    /** NOT EXCTRACTIBLE : Returns null. 
     * Returns the key in its primary encoding format, or null if this key does not support encoding. */
    public byte[] getEncoded() {
        // not extractible
        return null;
    }
          
    public String getFormat(){
        return CryptoAPIKeyFormat;
    } 
    
    public CAPIPrivateKey getCAPIPrivateKey(){
        return this.CAPIprivKey;
    }
}
