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

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import be.cardon.cryptoapi.CAPIHash;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;

/**This class must be extended.
 *
 * @author Rodolphe
 */
public abstract class CryptoAPISignature extends SignatureSpi{
    
    
    private CryptoAPIPrivateKey privKey;
    private int status;
    private static final int UNINITIALIZED = 0;
    private static final int SIGN = 1;
    private static final int VERIFY = 2;
    private String hashAlg; // MD5, MD2, SHA-1 
    private Signature signVerif; //for verification process
    private CAPIHash hash;       //for sign process
    private byte[] preHash;  //precalculated hash
    
    
    /** Creates a new instance of CryptoAPISignature */
    public CryptoAPISignature() {
    }
    
    protected void setHashAlgorithm(String hashAlg){
        this.hashAlg = hashAlg;
    }
    
    /**Returns a clone if the implementation is cloneable. */
    public Object clone(){
        return null;
    }
    
    /** Deprecated.*/
    protected Object engineGetParameter(String param){
        return null;
    } 
            
    /**This method is overridden by providers to return the parameters 
     * used with this signature engine, or null if this signature engine 
     * does not use any parameters. */    
    protected  AlgorithmParameters engineGetParameters(){
        return null;
    }

    /**Initializes this signature object with the specified private key for 
     * signing operations. */
    protected void engineInitSign(
            PrivateKey privateKey) throws InvalidKeyException{
        //check if the privateKey is a CryptoAPIPrivateKey
        if(!be.cardon.utils.OperatingSystem.isWindows()){
            throw new InvalidKeyException("Only available on Windows Operating System.");
        }
        if(!privateKey.getClass().equals(CryptoAPIPrivateKey.class)){
            throw new InvalidKeyException("the private key must be an instance of" +
                    "CryptoAPIPrivateKey.");
        }
        this.privKey = (CryptoAPIPrivateKey)privateKey;
        this.status = SIGN;
        int algID;
        try{
        algID = CAPIHash.StringToalgID(this.hashAlg);
        }catch(CryptoAPIException e){
            throw new InvalidKeyException("StringToalgID error :"+e.getMessage());
        }
        try{
        hash = this.privKey.getCAPIPrivateKey().createHash(algID);
        
        if(this.preHash != null){
            hash.setHashValue(preHash);
        }
        }catch(CryptoAPIException e){
            throw new InvalidKeyException("createHash error:"+e.getMessage());
        }        
    }
    
    /**Initializes this signature object with the specified private key (and 
     * source of randomness for signing operations => not used). */
    protected void engineInitSign(
            PrivateKey privateKey, 
            SecureRandom random) throws InvalidKeyException{
        engineInitSign(privateKey);
    } 
    
    /**Initializes this signature object with the specified public key for 
     * verification operations. */
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException{
        if(!be.cardon.utils.OperatingSystem.isWindows()){
            throw new InvalidKeyException("Only available on Windows Operating System.");
        }
        throw new InvalidKeyException("Verification not implemented. Use another provider instead.");
    } 
          
    /**This method is overridden by providers to initialize this signature 
     * engine with the specified parameter set. */
    protected void engineSetParameter(AlgorithmParameterSpec params){
        return;
    }
    /**Deprecated. Replaced by engineSetParameter.*/
    protected void engineSetParameter(String param, Object value)
    throws InvalidParameterException{
        if(param.equals("hash")){
            if(!(value instanceof byte[])){
                throw new InvalidParameterException("hash parameter value must be byte[] object.");
            }
            this.preHash = (byte[])value;
        }
    }
          
    /**Returns the signature bytes of all the data updated so far.*/
    protected byte[] engineSign() throws SignatureException{
        if(this.status!=SIGN){
            throw new SignatureException("initSign must be called first.");
        }
        try{
        return this.hash.signHash();
        }catch(CryptoAPIException e){
            throw new SignatureException(e.getMessage());
        }
    }
    
    /**Finishes this signature operation and stores the resulting signature 
     * bytes in the provided buffer outbuf, starting at offset. */
    protected int engineSign(byte[] outbuf, int offset, int len) throws SignatureException {
        byte[] signature = this.engineSign();
        if(len<signature.length){
            throw new SignatureException("buffer is too small");
        }
        System.arraycopy(signature, 0, outbuf, offset, signature.length);
        return signature.length;
    }
    
    /**Updates the data to be signed or verified using the specified byte array. */
    private void engineUpdate(byte[] data) throws SignatureException{
        if(this.status==SIGN){
            try{
                hash.hashData(data);
            }catch(CryptoAPIException e){
                throw new SignatureException(e.getMessage());
            }
        }else{
            throw new SignatureException("Engine is not properly initialised.");
        }
    } 
    /**Updates the data to be signed or verified using the specified byte. */
    protected void engineUpdate(byte b) throws SignatureException{
        byte[] data = {b};
        this.engineUpdate(data);
    } 
    /**Updates the data to be signed or verified, using the specified array of 
     * bytes, starting at the specified offset. */
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException{
        byte[] data = new byte[len];
        System.arraycopy(b, off, data, 0, len);
        this.engineUpdate(data);
    }
          
    /**Updates the data to be signed or verified using the specified ByteBuffer.
    protected void engineUpdate(ByteBuffer input) throws SignatureException{
    }
     */
          
    /**Verifies the passed-in signature. */
    protected boolean engineVerify(byte[] sigBytes)throws SignatureException{
        throw new SignatureException("not implemented");
    }
          
    /**Verifies the passed-in signature in the specified array of bytes, 
     * starting at the specified offset. */
    protected boolean engineVerify(byte[] sigBytes, int offset, int length)
      throws SignatureException{
        throw new SignatureException("not implemented");
    }
    
    public static class MD2 extends CryptoAPISignature {
        public MD2() {
            super();
            super.setHashAlgorithm("MD2");
       }
    }
        
    public static class MD5 extends CryptoAPISignature {
        public MD5() {
            super();
            super.setHashAlgorithm("MD5");
       }
    }
    public static class SHA1 extends CryptoAPISignature {
        public SHA1() {
            super();
            super.setHashAlgorithm("SHA-1");
       }
    }
    
}

