/*
 * Copyright 2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * $Id: SerializerMessages.java,v 1.9 2005/08/04 23:59:14 minchau Exp $
 */
package lib.org.apache.xml.serializer.utils;

import java.util.ListResourceBundle;

/**
 * An instance of this class is a ListResourceBundle that
 * has the required getContents() method that returns
 * an array of message-key/message associations.
 * <p>
 * The message keys are defined in {@link MsgKey}. The
 * messages that those keys map to are defined here.
 * <p>
 * The messages in the English version are intended to be
 * translated. 
 * 
 * This class is not a public API, it is only public because it is 
 * used in org.apache.xml.serializer.
 * 
 * @xsl.usage internal
 */
public class SerializerMessages extends ListResourceBundle {

    /*
     * This file contains error and warning messages related to
     * Serializer Error Handling.
     *
     *  General notes to translators:
    
     *  1) A stylesheet is a description of how to transform an input XML document
     *     into a resultant XML document (or HTML document or text).  The
     *     stylesheet itself is described in the form of an XML document.
    
     *
     *  2) An element is a mark-up tag in an XML document; an attribute is a
     *     modifier on the tag.  For example, in <elem attr='val' attr2='val2'>
     *     "elem" is an element name, "attr" and "attr2" are attribute names with
     *     the values "val" and "val2", respectively.
     *
     *  3) A namespace declaration is a special attribute that is used to associate
     *     a prefix with a URI (the namespace).  The meanings of element names and
     *     attribute names that use that prefix are defined with respect to that
     *     namespace.
     *
     *
     */

    /** The lookup table for error messages.   */
    public Object[][] getContents() {
        Object[][] contents = new Object[][] {
            {   MsgKey.BAD_MSGKEY,
                "The message key ''{0}'' is not in the message class ''{1}''" },
                
            {   MsgKey.BAD_MSGFORMAT,
                "The format of message ''{0}'' in message class ''{1}'' failed." },

            {   MsgKey.ER_SERIALIZER_NOT_CONTENTHANDLER,
                "The serializer class ''{0}'' does not implement org.xml.sax.ContentHandler." },

            {   MsgKey.ER_RESOURCE_COULD_NOT_FIND,
                    "The resource [ {0} ] could not be found.\n {1}" },

            {   MsgKey.ER_RESOURCE_COULD_NOT_LOAD,
                    "The resource [ {0} ] could not load: {1} \n {2} \t {3}" },

            {   MsgKey.ER_BUFFER_SIZE_LESSTHAN_ZERO, 
                    "Buffer size <=0" }, 

            {   MsgKey.ER_INVALID_UTF16_SURROGATE,
                    "Invalid UTF-16 surrogate detected: {0} ?" },

            {   MsgKey.ER_OIERROR, 
                "IO error" }, 

            {   MsgKey.ER_ILLEGAL_ATTRIBUTE_POSITION,
                "Cannot add attribute {0} after child nodes or before an element is produced.  Attribute will be ignored." },

            /*
             * Note to translators:  The stylesheet contained a reference to a
             * namespace prefix that was undefined.  The value of the substitution
             * text is the name of the prefix.
             */ 
            {   MsgKey.ER_NAMESPACE_PREFIX,
                "Namespace for prefix ''{0}'' has not been declared." },

            /*
             * Note to translators:  This message is reported if the stylesheet
             * being processed attempted to construct an XML document with an
             * attribute in a place other than on an element.  The substitution text
             * specifies the name of the attribute.
             */ 
            {   MsgKey.ER_STRAY_ATTRIBUTE,
                "Attribute ''{0}'' outside of element." },

            /*
             * Note to translators:  As with the preceding message, a namespace
             * declaration has the form of an attribute and is only permitted to
             * appear on an element.  The substitution text {0} is the namespace
             * prefix and {1} is the URI that was being used in the erroneous
             * namespace declaration.
             */ 
            {   MsgKey.ER_STRAY_NAMESPACE,
                "Namespace declaration ''{0}''=''{1}'' outside of element." },

            {   MsgKey.ER_COULD_NOT_LOAD_RESOURCE,
                "Could not load ''{0}'' (check CLASSPATH), now using just the defaults" },

            {   MsgKey.ER_ILLEGAL_CHARACTER,
                "Attempt to output character of integral value {0} that is not represented in specified output encoding of {1}." },

            {   MsgKey.ER_COULD_NOT_LOAD_METHOD_PROPERTY,
                "Could not load the propery file ''{0}'' for output method ''{1}'' (check CLASSPATH)" },

            {   MsgKey.ER_INVALID_PORT, 
                "Invalid port number" }, 

            {   MsgKey.ER_PORT_WHEN_HOST_NULL,
                "Port cannot be set when host is null" },

            {   MsgKey.ER_HOST_ADDRESS_NOT_WELLFORMED,
                "Host is not a well formed address" },

            {   MsgKey.ER_SCHEME_NOT_CONFORMANT,
                "The scheme is not conformant." },

            {   MsgKey.ER_SCHEME_FROM_NULL_STRING,
                "Cannot set scheme from null string" },

            {   MsgKey.ER_PATH_CONTAINS_INVALID_ESCAPE_SEQUENCE,
                "Path contains invalid escape sequence" },

            {   MsgKey.ER_PATH_INVALID_CHAR,
                "Path contains invalid character: {0}" },

            {   MsgKey.ER_FRAG_INVALID_CHAR,
                "Fragment contains invalid character" },

            {   MsgKey.ER_FRAG_WHEN_PATH_NULL,
                "Fragment cannot be set when path is null" },

            {   MsgKey.ER_FRAG_FOR_GENERIC_URI,
                "Fragment can only be set for a generic URI" },

            {   MsgKey.ER_NO_SCHEME_IN_URI, 
                "No scheme found in URI" }, 

            {   MsgKey.ER_CANNOT_INIT_URI_EMPTY_PARMS,
                "Cannot initialize URI with empty parameters" },

            {   MsgKey.ER_NO_FRAGMENT_STRING_IN_PATH,
                "Fragment cannot be specified in both the path and fragment" },

            {   MsgKey.ER_NO_QUERY_STRING_IN_PATH,
                "Query string cannot be specified in path and query string" },

            {   MsgKey.ER_NO_PORT_IF_NO_HOST,
                "Port may not be specified if host is not specified" },

            {   MsgKey.ER_NO_USERINFO_IF_NO_HOST,
                "Userinfo may not be specified if host is not specified" },

            {   MsgKey.ER_XML_VERSION_NOT_SUPPORTED,
                "Warning:  The version of the output document is requested to be ''{0}''.  This version of XML is not supported.  The version of the output document will be ''1.0''." },

            {   MsgKey.ER_SCHEME_REQUIRED, 
                "Scheme is required!" },
                
            /*
             * Note to translators:  The words 'Properties' and
             * 'SerializerFactory' in this message are Java class names
             * and should not be translated.
             */    
            {   MsgKey.ER_FACTORY_PROPERTY_MISSING,
                "The Properties object passed to the SerializerFactory does not have a ''{0}'' property." },

            {   MsgKey.ER_ENCODING_NOT_SUPPORTED,
                "Warning:  The encoding ''{0}'' is not supported by the Java runtime." },
                

        };

        return contents;
    }
}
