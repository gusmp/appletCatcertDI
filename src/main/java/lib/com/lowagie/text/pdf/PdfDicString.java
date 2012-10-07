/*
 * $Id: PdfName.java,v 1.83 2006/06/04 22:23:38 psoares33 Exp $
 * $Name:  $
 *
 * Copyright 1999-2006 Bruno Lowagie
 *
 * The contents of this file are subject to the Mozilla Public License Version 1.1
 * (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the License.
 *
 * The Original Code is 'iText, a free JAVA-PDF library'.
 *
 * The Initial Developer of the Original Code is Bruno Lowagie. Portions created by
 * the Initial Developer are Copyright (C) 1999, 2000, 2001, 2002 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2000, 2001, 2002 by Paulo Soares. All Rights Reserved.
 *
 * Contributor(s): all the names of the contributors are added in the source code
 * where applicable.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * LGPL license (the "GNU LIBRARY GENERAL PUBLIC LICENSE"), in which case the
 * provisions of LGPL are applicable instead of those above.  If you wish to
 * allow use of your version of this file only under the terms of the LGPL
 * License and not to allow others to use your version of this file under
 * the MPL, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the LGPL.
 * If you do not delete the provisions above, a recipient may use your version
 * of this file under either the MPL or the GNU LIBRARY GENERAL PUBLIC LICENSE.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MPL as stated above or under the terms of the GNU
 * Library General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Library general Public License for more
 * details.
 *
 * If you didn't download this code from the following link, you should check if
 * you aren't using an obsolete version:
 * http://www.lowagie.com/iText/
 */

package lib.com.lowagie.text.pdf;

/**
 * <CODE>PdfName</CODE> is an object that can be used as a name in a PDF-file.
 * <P>
 * A name, like a string, is a sequence of characters. It must begin with a slash
 * followed by a sequence of ASCII characters in the range 32 through 136 except
 * %, (, ), [, ], &lt;, &gt;, {, }, / and #. Any character except 0x00 may be included
 * in a name by writing its twocharacter hex code, preceded by #. The maximum number
 * of characters in a name is 127.<BR>
 * This object is described in the 'Portable Document Format Reference Manual version 1.3'
 * section 4.5 (page 39-40).
 * <P>
 *
 * @see		PdfObject
 * @see		PdfDictionary
 * @see		BadPdfFormatException
 */

public class PdfDicString extends PdfObject implements Comparable{
    
    private int hash = 0;
    
    // constructors
    

    /**
     * Constructs a new <CODE>PdfName</CODE>. The name length will be checked.
     * @param name the new name
     */
    public PdfDicString(String name) {
        this(name, true);
    }
    
    /**
     * Constructs a new <CODE>PdfName</CODE>.
     * @param name the new name
     * @param lengthCheck if <CODE>true</CODE> check the lenght validity, if <CODE>false</CODE> the name can
     * have any length
     */
    
    public PdfDicString(String name, boolean lengthCheck) {
        super(PdfObject.NAME);
        // The minimum number of characters in a name is 0, the maximum is 127 (the '/' not included)
        int length = name.length();
        //if (lengthCheck && length > 127) {
        //    throw new IllegalArgumentException("The name '" + name + "' is too long (" + length + " characters).");
        //}
        // The name has to be checked for illegal characters
        // every special character has to be substituted
        ByteBuffer pdfName = new ByteBuffer(length + 20);
        char character;
        char chars[] = name.toCharArray();
        // loop over all the characters
        for (int index = 0; index < length; index++) {
            character = (char)(chars[index] & 0xff);                    
            pdfName.append(character);
            }        
        bytes = pdfName.toByteArray();
    }
    
    /**
     * Constructs a PdfName.
     * @param bytes the byte representation of the name
     */
    public PdfDicString(byte bytes[]) {
        super(PdfObject.NAME, bytes);
    }
    // methods
    
    /**
     * Compares this object with the specified object for order.  Returns a
     * negative integer, zero, or a positive integer as this object is less
     * than, equal to, or greater than the specified object.<p>
     * @param object the Object to be compared.
     * @return a negative integer, zero, or a positive integer as this object
     * 		is less than, equal to, or greater than the specified object.
     * @throws ClassCastException if the specified object's type prevents it
     *         from being compared to this Object.
     */
    public int compareTo(Object object) {
        PdfName name = (PdfName) object;
        
        byte myBytes[] = bytes;
        byte objBytes[] = name.bytes;
        int len = Math.min(myBytes.length, objBytes.length);
        for(int i=0; i<len; i++) {
            if(myBytes[i] > objBytes[i])
                return 1;
            
            if(myBytes[i] < objBytes[i])
                return -1;
        }
        if (myBytes.length < objBytes.length)
            return -1;
        if (myBytes.length > objBytes.length)
            return 1;
        return 0;
    }
    
    /**
     * Indicates whether some other object is "equal to" this one.
     *
     * @param   obj   the reference object with which to compare.
     * @return  <code>true</code> if this object is the same as the obj
     *          argument; <code>false</code> otherwise.
     */
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj instanceof PdfName)
            return compareTo(obj) == 0;
        return false;
    }
    
    /**
     * Returns a hash code value for the object. This method is
     * supported for the benefit of hashtables such as those provided by
     * <code>java.util.Hashtable</code>.
     *
     * @return  a hash code value for this object.
     */
    public int hashCode() {
        int h = hash;
        if (h == 0) {
            int ptr = 0;
            int len = bytes.length;
            
            for (int i = 0; i < len; i++)
                h = 31*h + (bytes[ptr++] & 0xff);
            hash = h;
        }
        return h;
    }
    
    /** Decodes an escaped name in the form "/AB#20CD" into "AB CD".
     * @param name the name to decode
     * @return the decoded name
     */
    public static String decodeName(String name) {
        StringBuffer buf = new StringBuffer();
        try {
            int len = name.length();
            for (int k = 1; k < len; ++k) {
                char c = name.charAt(k);
                if (c == '#') {
                    c = (char)((PRTokeniser.getHex(name.charAt(k + 1)) << 4) + PRTokeniser.getHex(name.charAt(k + 2)));
                    k += 2;
                }
                buf.append(c);
            }
        }
        catch (IndexOutOfBoundsException e) {
            // empty on purpose
        }
        return buf.toString();
    }
}
