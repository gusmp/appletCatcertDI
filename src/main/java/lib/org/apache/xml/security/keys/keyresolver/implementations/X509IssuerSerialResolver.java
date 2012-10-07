
/*
 * Copyright  1999-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package lib.org.apache.xml.security.keys.keyresolver.implementations;



import java.security.PublicKey;
import java.security.cert.X509Certificate;

import lib.org.apache.xml.security.exceptions.XMLSecurityException;
import lib.org.apache.xml.security.keys.content.X509Data;
import lib.org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import lib.org.apache.xml.security.keys.keyresolver.KeyResolverException;
import lib.org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import lib.org.apache.xml.security.keys.storage.StorageResolver;
import lib.org.apache.xml.security.signature.XMLSignatureException;
import lib.org.apache.xml.security.utils.Constants;

import org.w3c.dom.Element;


/**
 *
 * @author $Author: raul $
 */
public class X509IssuerSerialResolver extends KeyResolverSpi {

    /** @inheritDoc */
   public boolean engineCanResolve(Element element, String BaseURI,
                                   StorageResolver storage) {

      X509Data x509data = null;
      try {
         x509data = new X509Data(element, BaseURI);
      } catch (XMLSignatureException ex) {

         return false;
      } catch (XMLSecurityException ex) {

         return false;
      }

      if (x509data == null) {
         return false;
      }

      if (x509data.containsIssuerSerial()) {
            return true;
      }

      return false;
   }

   /** @inheritDoc */
   public PublicKey engineResolvePublicKey(
           Element element, String BaseURI, StorageResolver storage)
              throws KeyResolverException {

      X509Certificate cert = this.engineResolveX509Certificate(element,
                                BaseURI, storage);

      if (cert != null) {
         return cert.getPublicKey();
      }

      return null;
   }

   /** @inheritDoc */
   public X509Certificate engineResolveX509Certificate(
           Element element, String BaseURI, StorageResolver storage)
              throws KeyResolverException {

      try {
         if (storage == null) {
            Object exArgs[] = { Constants._TAG_X509ISSUERSERIAL };
            KeyResolverException ex =
               new KeyResolverException("KeyResolver.needStorageResolver",
                                        exArgs);

            throw ex;
         }

         X509Data x509data = new X509Data(element, BaseURI);
         int noOfISS = x509data.lengthIssuerSerial();

         while (storage.hasNext()) {
            X509Certificate cert = storage.next();
            XMLX509IssuerSerial certSerial = new XMLX509IssuerSerial(element.getOwnerDocument(), cert);


            for (int i=0; i<noOfISS; i++) {
               XMLX509IssuerSerial xmliss = x509data.itemIssuerSerial(i);

               if (certSerial.equals(xmliss)) {

                  return cert;
               }                
            }
         }

         return null;
      } catch (XMLSecurityException ex) {

         throw new KeyResolverException("generic.EmptyMessage", ex);
      }
   }

   /** @inheritDoc */
   public javax.crypto.SecretKey engineResolveSecretKey(
           Element element, String BaseURI, StorageResolver storage) {
      return null;
   }
}
