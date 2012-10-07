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
package lib.org.apache.xml.security.utils.resolver.implementations;



import lib.org.apache.xml.security.signature.XMLSignatureInput;
import lib.org.apache.xml.security.utils.IdResolver;
import lib.org.apache.xml.security.utils.resolver.ResourceResolverException;
import lib.org.apache.xml.security.utils.resolver.ResourceResolverSpi;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Node;


/**
 * This resolver is used for resolving same-document URIs like URI="" of URI="#id".
 *
 * @author $Author: dims $
 * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel">The Reference processing model in the XML Signature spec</A>
 * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#sec-Same-Document">Same-Document URI-References in the XML Signature spec</A>
 * @see <A HREF="http://www.ietf.org/rfc/rfc2396.txt">Section 4.2 of RFC 2396</A>
 */
public class ResolverFragment extends ResourceResolverSpi {


   /**
    * Method engineResolve
    *
    * Wird das gleiche Dokument referenziert?
    * Wird ein anderes Dokument referenziert?
    * @inheritDoc
    * @param uri
    * @param BaseURI
    *
    */
   public XMLSignatureInput engineResolve(Attr uri, String BaseURI) 
       throws ResourceResolverException
   {

      String uriNodeValue = uri.getNodeValue();
      Document doc = uri.getOwnerElement().getOwnerDocument();


      Node selectedElem = null;
      if (uriNodeValue.equals("")) {

         /*
          * Identifies the node-set (minus any comment nodes) of the XML
          * resource containing the signature
          */

	 selectedElem = doc;
      } else {

         /*
          * URI="#chapter1"
          * Identifies a node-set containing the element with ID attribute
          * value 'chapter1' of the XML resource containing the signature.
          * XML Signature (and its applications) modify this node-set to
          * include the element plus all descendents including namespaces and
          * attributes -- but not comments.
          */
         String id = uriNodeValue.substring(1);

         // Element selectedElem = doc.getElementById(id);
         selectedElem = IdResolver.getElementById(doc, id);
         if (selectedElem==null) {
         	Object exArgs[] = { id };
            throw new ResourceResolverException(
               "signature.Verification.MissingID", exArgs, uri, BaseURI);
         }
      }

      XMLSignatureInput result = new XMLSignatureInput(selectedElem);
      result.setExcludeComments(true);

      //log.debug("We return a nodeset with " + resultSet.size() + " nodes");
      result.setMIMEType("text/xml");	  
	  result.setSourceURI((BaseURI != null) ? BaseURI.concat(uri.getNodeValue()) :
		  uri.getNodeValue());      
      return result;
   }

   /**
    * Method engineCanResolve
    * @inheritDoc
    * @param uri
    * @param BaseURI
    *
    */
   public boolean engineCanResolve(Attr uri, String BaseURI) {

      if (uri == null) {
         return false;
      }

      String uriNodeValue = uri.getNodeValue();

      if (uriNodeValue.equals("")
              || ((uriNodeValue.charAt(0)=='#')
                  &&!uriNodeValue.startsWith("#xpointer("))) {
         return true;
      }
      return false;
   }

}
