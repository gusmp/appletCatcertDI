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

/**The <i>Microsoft CryptoAPI</i> bridge provider. 
 * <p>This provider extends the <i>java.security.Provider</i> class. For 
 * documentation about the cryptographic providers architecture, search
 * 'Security' in the Java SDK.</p>
 * <p>The provider contains :<br>
 * <li>a KeyStore engine of type "<i>CryptoAPI</i>",</li>
 * <li>a Signature engine (algorithm supported : [MD5|SHA1|MD2]with[RSA|DSA]).
 * You can also use "CryptoAPI-MD5", "CryptoAPI-SHA1", or "CryptoAPI-MD2" to 
 * identify unambiguous this provider.</li>
 * </p>
 * <p><b>The signature engine doesn't support verification !</b>. Be sure to
 * use another provider (like SUN) to apply a verification algorithm. 
 * <i>CryptoAPI Provider</i> should not be installed in first position.</p>
 
 * @author CARDON DE LICHTBUER Rodolphe, rodolphe@wol.be
 */
public class CryptoAPIProvider extends java.security.Provider{

    public CryptoAPIProvider() { 
            super("MicrosoftCryptoAPIBridge", 1.0, "Microsoft Crypto API Bridge Provider"); 

            //MD5
            String MD5Provider = CryptoAPISignature.MD5.class.getName();
            put("Signature.MD5withRSA", MD5Provider);
            put("Signature.MD5withDSA", MD5Provider);            
            put("Signature.CryptoAPI-MD5", MD5Provider);            
 
            //SHA1
            String SHA1Provider = CryptoAPISignature.SHA1.class.getName(); 
            put("Signature.SHA1withRSA", SHA1Provider);
            put("Signature.SHA1withDSA",  SHA1Provider);
            put("Signature.CryptoAPI-SHA1", SHA1Provider);            

            //MD2
           String MD2Provider = CryptoAPISignature.MD2.class.getName();
            put("Signature.MD2withRSA", MD2Provider);
            put("Signature.MD2withDSA", MD2Provider);
            put("Signature.CryptoAPI-MD2", MD2Provider);
            
            //KeyStore
            String KeyStoreProvider = CryptoAPIKeyStore.class.getName();
            put("KeyStore.CryptoAPI", KeyStoreProvider);
    }
}
