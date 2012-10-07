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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import be.cardon.cryptoapi.provider.PINNotSupportedException;
import be.cardon.nativecall.LowLevelCalls;
import be.cardon.nativecall.NativeByteArray;
import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.cryptoapi.Constants;
import be.cardon.nativecall.cryptoapi.CryptoAPICalls;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;
/**
 *
 * @author CARDON DE LICHTBUER Rodolphe
 */
public class CAPIPrivateKey {
 
    /** CryptProv handle.*/
    private int hCryptProv;
    
    /** dwKeySpec.*/
    private int dwKeySpec;
    
    /** fCallerFreeProv*/
    boolean fCallerFreeProv;
    
    /** encoding used to convert char[] password to byte.*/
    private static String passwordEncoding = "UTF-8";

    /** PIN.*/
    private NativeByteArray pinBytes;

    /** Creates a new instance of CAPIPrivateKey, with the given Certificate Context handle, and the given flags.
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
    public CAPIPrivateKey(CAPICertificate cert, int dwFlags, char[] password) throws CryptoAPIException{
        try{
        CryptoAPICalls calls = new CryptoAPICalls();
        int pCert = cert.GetNativeStructCERT_CONTEXT().getAddress();
        LowLevelCalls LC = new LowLevelCalls();
        int[] cryptAcqPriKeyReturn = calls.CryptAcquireCertificatePrivateKey(pCert,dwFlags);
        this.hCryptProv = LC.readInt(cryptAcqPriKeyReturn[0]);
        this.dwKeySpec = LC.readInt(cryptAcqPriKeyReturn[1]);
        this.fCallerFreeProv = (cryptAcqPriKeyReturn[2]==1);
        
        //if password is defined, converts to byte and call CryptSetProvParam
        if(password!=null){
            ByteArrayOutputStream bytestream = new ByteArrayOutputStream();
            bytestream.write(new String(password).getBytes(this.getPasswordEncoding()));
            bytestream.write(new Byte("0")); 
            bytestream.write(new Byte("0"));
            pinBytes = new NativeByteArray(bytestream.size());
            pinBytes.write(bytestream.toByteArray());
            
            int pinType;
            if(dwKeySpec==Constants.AT_KEYEXCHANGE){
                pinType = Constants.PP_KEYEXCHANGE_PIN;
            }else if(dwKeySpec==Constants.AT_SIGNATURE){
                pinType = Constants.PP_SIGNATURE_PIN;
            }else{
                throw new NativeCallException(
                        "Undefined key type. dwKeySpec="+ dwKeySpec);
            }
            try{
            calls.CryptSetProvParam(this.hCryptProv, pinType, 
                    pinBytes.getAddress(), 0);
            }catch(CryptoAPIException e2){
                throw new PINNotSupportedException();
            }
        }
        
        }catch(NativeCallException e){
            throw new CryptoAPIException("NativeCallException", e);
        }catch(UnsupportedEncodingException e){
            throw new CryptoAPIException("Password encoding not supported: "+
                    this.passwordEncoding, e);
        }catch(IOException e){
            throw new CryptoAPIException(e);
        }
    }

    /** Creates a new instance of CAPIPrivateKey, with the given Certificate Context handle, and no flag.
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
    public CAPIPrivateKey(CAPICertificate cert, char[] password)  throws CryptoAPIException{
           this(cert, 0, password);
     }
    
    /** Create hash with the given algorithm*/
    public CAPIHash createHash(int alg) throws CryptoAPIException{
        return CAPIHash.createHash(this, alg);
    }
    
    public void finalize() throws java.lang.Throwable
    {
        if(fCallerFreeProv){
            new CryptoAPICalls().CryptReleaseContext(hCryptProv);
        }
        super.finalize();
    }
    
    public int hCryptProv(){
        return this.hCryptProv;
    }
    public int dwKeySpec(){
        return this.dwKeySpec;
    }    
    
    /** Returns the encoding used to convert char[] password to byte.*/
    public String getPasswordEncoding() {
        return passwordEncoding;
    }
    
    /** Set the encoding used to convert char[] password to byte.*/
    public void setPasswordEncoding(String encoding) {
        this.passwordEncoding = encoding;
    }
}
