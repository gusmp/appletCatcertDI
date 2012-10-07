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

package be.cardon.nativecall;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;


/**{@code NULL} terminated Unicode string (UTF-16LE) native object.
 * @author CARDON Rodolphe
 */
public class NativeUnicodeString extends NativeObject{
    
    /**Private constructor. Allocates and copies the byte array.
     */
    private NativeUnicodeString(byte[] stringByteArray) throws NativeCallException{
        super(stringByteArray.length);
        new LowLevelCalls().writeBytes(this.getAddress(), stringByteArray);
    }
    
    /**Copy a given string to new allocated {@code NULL} terminated Unicode 
     * (2 bytes/char)string  {@code wchar[]}.
     * The given string is converted to UTF-16 <b>little endian</b> sinds
     * x386 processor works natively in little endian (Java works in big endian on
     * any platform). The native string is terminated with 1 NULL character (= 2 bytes 
     * {@code NULL}).
     *@param str String to be copied.
     *@return {code NativeUnicodeString} native object. This object extends the {@link NativeObject NativeObject}.
     */
    public static NativeUnicodeString newInstance(String str) throws NativeCallException{
        try{
            ByteArrayOutputStream bytestream = new ByteArrayOutputStream();
            bytestream.write(str.getBytes("UTF-16LE")); // Little Endian
            bytestream.write(new Byte("0"));
            bytestream.write(new Byte("0"));
            byte[] stringByteArray = bytestream.toByteArray();
            return new NativeUnicodeString(stringByteArray);

        }catch(UnsupportedEncodingException e){
            throw new NativeCallException("UTF-16LE encoding not supported", e);
        }catch(IOException e){
            throw new NativeCallException("Unexpected IO error while constructing the string stream", e);
        }
    }
}
