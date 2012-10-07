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

 * CryptoAPIKeyStore2.java
 * version 2 of CryptoAPIKeyStore
 * support for (Trusted)Certificates
 *
 * Created on 8 août 2006, 19:06
 *
 * limitation : read only (add/delete not allowed)
 *
 */
package be.cardon.cryptoapi.provider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import be.cardon.cryptoapi.CAPICertificate;
import be.cardon.cryptoapi.CAPICertificateChain;
import be.cardon.cryptoapi.CAPIStore;
import be.cardon.nativecall.cryptoapi.CryptoAPIException;



/**CryptoAPI store wrapper
 *
 * @author Rodolphe
 */
public class CryptoAPIKeyStore extends KeyStoreSpi{
    
    private CAPIStore store=null;
    
    /** Creates a new instance of CryptoAPIKeyStore */
    public CryptoAPIKeyStore() throws java.io.IOException {
        //store = CAPIStore.openMyStore();
    }
    
    /** Lists all the alias names of this keystore.*/
    public Enumeration<String> engineAliases(){
        return new EnumAliases();
    }
    
    /** Enumeration of keys aliases*/
    public class EnumAliases implements Enumeration<String>{
        
        private Iterator iteratorStore;
        
        /** Create an instance of EnumAlias.*/
        public EnumAliases(){
            iteratorStore = store.iterator();
        }
        
        /** Returns the next alias string.*/
        public String nextElement() {
            try{
                return getAlias((CAPICertificate)iteratorStore.next());
            }catch(CryptoAPIException e){
                e.printStackTrace();
                return null;
            }
        }
        
        /** Returns true if there are more aliases in the keystore.*/
        public boolean hasMoreElements(){
            return iteratorStore.hasNext();
        }
    };
    
    /**Checks if the given alias exists in this keystore.*/
    public boolean engineContainsAlias(String alias){
        /* Cette fonction parcourt tous les alias et les compare avec l'alias donné.*/
        for(Enumeration<String> aliases = this.engineAliases(); aliases.hasMoreElements();){
            if(aliases.nextElement().equals(alias)){
                return true;
            }
        }
        return false;
    }
    
    /**NOT IMPLEMENTED : throw KeyStoreException.
     * Deletes the entry identified by the given alias from this keystore.*/
    public void engineDeleteEntry(String alias)throws java.security.KeyStoreException{
        /*interdit*/
        throw new java.security.KeyStoreException("not allowed");
    }
    
    
    /**Returns the certificate associated with the given alias.
     * or null if the given alias does not exist or does not contain a certificate.*/
    public Certificate engineGetCertificate(String alias) {
        CAPICertificate CAPICert = this.engineGetCAPICertificate(alias);
        if(CAPICert==null){
            return null;
        }else{
            try{
                return CAPICert.getCertificate();
            }catch(java.security.cert.CertificateException e){
                e.printStackTrace();
                return null;
            }catch(CryptoAPIException e){
                e.printStackTrace();
                return null;
            }
        }
    }
    
    /**Returns the CAPICertificate associated with the given alias.
     * or null if the given alias does not exist or does not contain a certificate.*/
    private CAPICertificate engineGetCAPICertificate(String alias) {
        try{
            for(Iterator<CAPICertificate> it = store.iterator(); it.hasNext();){
                CAPICertificate cert = it.next();
                if(getAlias(cert).equals(alias)){
                    return cert;
                }
            }
            return null; // alias not found
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }
    /**Returns the (alias) name of the first keystore entry whose certificate matches the given certificate,
     * or null if no such entry exists in this keystore. */
    public String engineGetCertificateAlias(Certificate cert) {
        /*compare chaque certificat avec le certificat donné.*/
        try{
            for(Iterator<CAPICertificate> it=store.iterator();it.hasNext();){
                CAPICertificate CAPICert = it.next();
                if(cert.equals(CAPICert.getCertificate())){
                    return getAlias(CAPICert);
                }
            }
            return null; // Entry not found
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }
    
    /** Returns the entry alias (not standard format : IssuerRND/SN:IssuerSN) */
    private static String getAlias(CAPICertificate CAPIcert) throws CryptoAPIException {
        return CAPIcert.getIssuerRDN()+ "/SN:" + CAPIcert.getIssuerSerialNumber();
    }
    
    /**Returns the certificate chain associated with the given alias.*/
    public Certificate[] engineGetCertificateChain(String alias) {
        
        try{
            CAPICertificate CAPIcert = this.engineGetCAPICertificate(alias);
            if(CAPIcert==null || !CAPIcert.hasPrivateKey()){
                return null;
            }
            CAPICertificateChain CAPIchain = new CAPICertificateChain(CAPIcert);
            CAPICertificate[] CAPIcerts = CAPIchain.getCertificateChain();
            if(CAPIcerts==null){return null;}
            
            Certificate[] certs = new Certificate[CAPIcerts.length];
            for(int it=0;it<CAPIcerts.length;it++){
                certs[it] = CAPIcerts[it].getCertificate();
            }
            return certs;
            
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }
    
    /**Returns the creation date of the entry identified by the given alias.*/
    public Date engineGetCreationDate(String alias) {
        /* ? possible ou pas ? je pense que non */
        return null;
    }
    
    /* Gets a KeyStore.Entry for the specified alias with the specified protection parameter.*/
    //engineGetEntry(String alias, KeyStore.ProtectionParameter protParam)
    
    /**Returns the key associated with the given alias. 
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
     *@throws java.security.UnrecoverableKeyException if the CryptSetProvParam function is not supported
     *for PIN, or other error.
     */
    public Key engineGetKey(String alias, char[] password)
    throws java.security.UnrecoverableKeyException{
        try{
            if(password!= null && new String(password).equals("")){
                password=null;
            }
            
            return (Key) new CryptoAPIPrivateKey(this.engineGetCAPICertificate(alias), password);
        }catch(CryptoAPIException e){
            if(e instanceof PINNotSupportedException){
                throw new java.security.UnrecoverableKeyException("PIN not supported by CSP.");  
            }else{
                System.err.println("Windows LastError : "+be.cardon.nativecall.LastError.getLastError());
            }
            throw new java.security.UnrecoverableKeyException(e.getMessage());
        }
    }
    
    /**Returns true if the entry identified by the given alias was created by a
     * call to setCertificateEntry, or created by a call to setEntry with a
     * TrustedCertificateEntry.*/
    public boolean engineIsCertificateEntry(String alias) {
        try{
            CAPICertificate CAPIcert = this.engineGetCAPICertificate(alias);
            if(CAPIcert==null || CAPIcert.hasPrivateKey()){
                return false;
            }else{return true;}
        }catch(CryptoAPIException e){
            e.printStackTrace();
            return false;
        }
    }
    
    /**Returns true if the entry identified by the given alias was created by a
     * call to setKeyEntry, or created by a call to setEntry with a
     * PrivateKeyEntry or a SecretKeyEntry.*/
    public boolean engineIsKeyEntry(String alias) {
        try{
            CAPICertificate CAPIcert = this.engineGetCAPICertificate(alias);
            if(CAPIcert==null || !CAPIcert.hasPrivateKey()){
                return false;
            }else{return true;}
        }catch(CryptoAPIException e){
            e.printStackTrace();
            return false;
        }
    }
    
    /**Loads the keystore from the given input stream. Inputstream is the UTF-8 name of
     * the MS store. If the inputstream is null, uses 'My' store. password is not used*/
    public void engineLoad(InputStream stream, char[] password) throws IOException{
        try{
            if(!be.cardon.utils.OperatingSystem.isWindows()){
                throw new IOException("KeyStore only available on Windows Operating System.");
            }
            if(stream==null){
                store = CAPIStore.openMyStore();
            }else{
                BufferedReader reader = new BufferedReader(new InputStreamReader(stream,"UTF-8"));
                String storeName = (String) reader.readLine();
                store = CAPIStore.openStore(storeName);
            }
        }catch(CryptoAPIException e){
            e.printStackTrace();
            throw new IOException("Error with opening the MS Store: "+e.getMessage());
        }
    }
    
    /*Loads the keystore using the given KeyStore.LoadStoreParameter.*/
    /*
    public void engineLoad(KeyStore.LoadStoreParameter param) {
     
    }*/
    
    /**Assigns the given certificate to the given alias.*/
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException{
        /*interdit*/
        throw new KeyStoreException("Not implemented.");
    }
    
    /*engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam)*/
    
    /**Assigns the given key (that has already been protected) to the given alias.*/
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        /*interdit*/
        throw new KeyStoreException("Not implemented.");
    }
    
    /** Assigns the given key to the given alias, protecting it with the given password.*/
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException{
        /*interdit*/
        throw new KeyStoreException("Not implemented.");
    }
    
    /**Retrieves the number of entries in this keystore.*/
    public int engineSize(){
        int count = 0;
        for(Enumeration<String> aliases = this.engineAliases();aliases.hasMoreElements();){
            aliases.nextElement();
            count++;
        }
        return count;
    }
    
    /**Stores this keystore using the given KeyStore.LoadStoreParmeter.*/
   /*
    public void engineStore(KeyStore.LoadStoreParameter param){
    
    }
    */
    
    public void engineStore(OutputStream stream, char[] password){
        /*do nothing, unmodified*/
        System.err.println("engineStore not implemented !!");
        return; //do nothing
    }
}