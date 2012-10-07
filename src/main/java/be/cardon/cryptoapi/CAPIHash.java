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

import be.cardon.nativecall.cryptoapi.Constants;
import be.cardon.nativecall.cryptoapi.CryptoAPICalls;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;
import be.cardon.utils.ByteArrayTools;


/**
 *
 * @author Rodolphe
 */
public class CAPIHash{
    
    /**handle of the hash*/
    private int hashHandle;
    private CAPIPrivateKey privKey;
    
    /** Creates a new instance of CAPIHash */
    public CAPIHash(int hashHandle) throws CryptoAPIException {
        if(hashHandle==0){
            throw new CryptoAPIException("Hash handle is zero.");
        }
        this.hashHandle = hashHandle;
    }
    
    /** Creates a new Hash with the given privateKey (used  after to sign the 
     * hash), and the algorithm (see be.cardon.nativecall.cryptoapi.Constants :
     * CALG_SHA1, CALG_MD5, ...)*/
    static CAPIHash createHash(CAPIPrivateKey privKey, int algID) throws CryptoAPIException{
        CAPIHash hash = createHash(privKey.hCryptProv(), algID);
        hash.privKey = privKey;
        return hash;
    }
    
    
     /** Creates a new Hash with the given hCryptProv (handle to the CSP), and 
      * the algorithm (see be.cardon.nativecall.cryptoapi.Constants :
     * CALG_SHA1, CALG_MD5, ...)*/
    static CAPIHash createHash(int hCryptProv, int algID) throws CryptoAPIException{
        return createHash(hCryptProv, algID, 0);
    }
    
    /** Creates a new Hash (MAC or not) with the given hCryptProv (handle to the CSP), and 
      * the algorithm (see be.cardon.nativecall.cryptoapi.Constants :
      * CALG_SHA1, CALG_MD5, ...)*/
    static CAPIHash createHash(int hCryptProv, int algID, int hKey) throws CryptoAPIException{
        int hashHandle = new CryptoAPICalls().CryptCreateHash(hCryptProv,algID, hKey);
        return new CAPIHash(hashHandle);
    }
    
    /** Sign the Hash. Returns the signature in big endian. This function may be 
     * used only if the hash has been created using c
     * reateHash(CAPIPrivateKey privKey, int algID)*/
    public byte[] signHash()throws CryptoAPIException{
        if(this.privKey==null){
            throw new CryptoAPIException("signHash error : this function may be " +
                    "used only if the hash has been created using"+
                    "createHash(CAPIPrivateKey privKey, int algID). See documentation.");
        }
        int dwKeySpec = privKey.dwKeySpec();
        int dwFlags = 0;
        return signHash(dwKeySpec, dwFlags);
    }
    
    /** Sign the hash, with the given key specifications and optional flags. 
     Returns the signature in big endian.*/
    public byte[] signHash(int dwKeySpec, int dwFlags) throws CryptoAPIException{
        byte[] littleEndianSign = 
                new CryptoAPICalls().CryptSignHash(this.hashHandle,dwKeySpec, dwFlags);
        byte[] bigEndianSign = ByteArrayTools.reverseByteArray(littleEndianSign);
        return bigEndianSign;
    }
    
    /** Hash data*/
    public void hashData(byte[] data, int dwFlags) throws CryptoAPIException{
        new CryptoAPICalls().CryptHashData(this.hashHandle, data, dwFlags);
    }
    
    /** Hash data (no flags)*/
    public void hashData(byte[] data) throws CryptoAPIException{
        int dwFlags=0;
        this.hashData(data, dwFlags);
    }
    
            
    public void finalize() throws Throwable{
        new CryptoAPICalls().CryptDestroyHash(this.hashHandle);
        super.finalize();
    }
    
    public static int StringToalgID(String hashAlgorithm) throws CryptoAPIException{
        Constants CST = new Constants();
        if(hashAlgorithm.equalsIgnoreCase("SHA-1") | hashAlgorithm.equalsIgnoreCase("SHA1")){
            return CST.CALG_SHA1;
        }else if(hashAlgorithm.equalsIgnoreCase("MD5")){
            return CST.CALG_MD5;
        }else if(hashAlgorithm.equalsIgnoreCase("MD2")){
            return CST.CALG_MD2;
        }else{
            throw new CryptoAPIException("unknown hashAlgorithm");
        }
    }
    
    /**Set the hash value. 
     * 
     *A byte array that contains a hash value to place directly into the hash object.
     */
    public void setHashValue(byte[] hash) throws CryptoAPIException{
        //http://msdn2.microsoft.com/en-us/library/aa380270(VS.85).aspx
        
        //from big to little endian
        byte[] littleEndianSign = ByteArrayTools.reverseByteArray(hash);
        
        //first check the length
        byte[] lengthWORD = new CryptoAPICalls().CryptGetHashParam(hashHandle, Constants.HP_HASHSIZE);
        byte[] bigEndianlengthWORD = ByteArrayTools.reverseByteArray(lengthWORD);
        int length=0;
        for(int i=0;i<bigEndianlengthWORD.length;i++){
            length += new Byte(bigEndianlengthWORD[bigEndianlengthWORD.length-i]).intValue() * 256^i;
        }
        if(length != littleEndianSign.length){
            throw new CryptoAPIException("bad hash length. Required: +"+length+". Given:"+littleEndianSign.length);
        }
        
        new CryptoAPICalls().CryptSetHashParam(hashHandle, Constants.HP_HASHVAL, littleEndianSign);
    }
    
}
