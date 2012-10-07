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
package lib.org.apache.xml.security.keys.content.x509;



import lib.org.apache.xml.security.exceptions.XMLSecurityException;
import lib.org.apache.xml.security.utils.Constants;
import lib.org.apache.xml.security.utils.SignatureElementProxy;

import org.w3c.dom.Document;
import org.w3c.dom.Element;


/**
 *
 *
 *
 *
 * @author $Author: raul $
 *
 */
public class XMLX509CRL extends SignatureElementProxy
        implements XMLX509DataContent {

   /**
    * Constructor XMLX509CRL
    *
    * @param element
    * @param BaseURI
    * @throws XMLSecurityException
    */
   public XMLX509CRL(Element element, String BaseURI)
           throws XMLSecurityException {
      super(element, BaseURI);
   }

   /**
    * Constructor X509CRL
    *
    * @param doc
    * @param crlBytes
    */
   public XMLX509CRL(Document doc, byte[] crlBytes) {

      super(doc);

      this.addBase64Text(crlBytes);
   }

   /**
    * Method getCRLBytes
    *
    * @return the CRL bytes
    * @throws XMLSecurityException
    */
   public byte[] getCRLBytes() throws XMLSecurityException {
      return this.getBytesFromTextChild();
   }

   /** @inheritDoc */
   public String getBaseLocalName() {
      return Constants._TAG_X509CRL;
   }
}
