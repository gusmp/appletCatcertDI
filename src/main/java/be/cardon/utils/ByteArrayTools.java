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

package be.cardon.utils;

/**Reverses a byte array, or compares two byte arrays.
 * @author Rodolphe
 */
public class ByteArrayTools {
    
    /** Reverse the byte order of a byte array.
     * Use this function for small byte arrays (this function use a copy of the array, so 
     * don't use it for big arrays)
     */
    public static byte[] reverseByteArray(byte[] byteArray){
        byte[] reverseByteArray = new byte[byteArray.length];
        for(int i=0;i<byteArray.length;i++){
            reverseByteArray[i] = byteArray[byteArray.length-1-i];
        };
        return reverseByteArray;
    }
    
    /**Compare two byte arrays. 
     * Returns {@code true} if the size of two arrays are equal {@code AND} if
     * each byte of the arrays are equal.
     */
    public static boolean equals(byte[] a, byte[] b){
        if(a.length!=b.length){
            return false;
        }
        int len = a.length;
        for(int i=0; i<len;i++){
            if(a[i]!=b[i]){
                return false;
            }
        } 
        return true;
    }
}
