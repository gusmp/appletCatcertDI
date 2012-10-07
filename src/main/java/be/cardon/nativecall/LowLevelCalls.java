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

/**Functions to allocate, delete, read or write some native types {@code int}, {@code boolean}, {@code byte}, 
 * UTF-8 String, etc.
 * <p>This class uses the Java Native Interface.
 * </p>
 *
 * <p><b>Note :</b>
 * In native object on Intel x386 processors, muliple byte values 
 * are encoded in <i>little endian</i> (first byte is the least significant 
 * byte) while Java use <i>big endiang</i> encoding (first byte is the most
 * significant byte). The functions in this class don't convert the byte arrays.
 * Use {@link be.cardon.utils#ByteArrayTools.reverseByteArray}
 * to reverse small byte arrays (this function use a copy of the array, so 
 * don't use it for big arrays).
 * </p>
 * @author Rodolphe
 */
public class LowLevelCalls {
    
    
    private static boolean _initialized = false;
    
    /** Creates a new instance of {code LowLevelCalls} 
     *The library {@code nativecall} is statically loaded when the first
     *instance of {code LowLevelCalls} is created.
     */
    public LowLevelCalls() throws NativeCallException{
        if(_initialized){
            return;
        }
        if(!be.cardon.utils.OperatingSystem.isWindows()){
            throw new NativeCallException("NativeCall only available on Windows.");
        }
        try{
        be.cardon.utils.LibraryLoader.loadLib("nativecall.dll");
        
        _initialized = true;
        }catch(Exception e){
            throw new NativeCallException(e);
        }
    }

    
    /**Read a signed integer (32 bits) at the given address */
    public native int readInt(int IntAddress)throws NativeCallException;

    /**Write a signed integer (32 bits) at the given address */
    public native void writeInt(int IntAddress, int value)
    throws NativeCallException;
    
    /**Read a signed short (16 bits) at the given address */
    public native short readShort(int IntAddress)
    throws NativeCallException;
    
    /**Read a UTF-8 String at the given address*/
    public native String readUTFString(int StringAddress)
    throws NativeCallException;
    
    /**Read a MS UNICODE String at the given address*/
    public native String readUnicodeString(int StringAddress)
    throws NativeCallException;
    
    /**Read a boolean at the given address*/
    public native boolean readBoolean(int BooleanAddress)
    throws NativeCallException;
    
    /**Write a boolean at the given address*/
    public native void writeBoolean(int BooleanAddress, boolean bool)
    throws NativeCallException;
    
    /**Read a byte array. 
     * See the note about byte order in this class description. 
     */
    public native byte[] readBytes(int firstByteAddress, int numberOfBytes)
    throws NativeCallException;
    
     /**Read one byte. 
      */
    public byte readByte(int ByteAddress)
    throws NativeCallException{
        int numberOfBytes = 1;
        byte[] bytes = this.readBytes(ByteAddress, numberOfBytes);
        return bytes[0];
    }
    
    /** Allocates memory and copies the given byte array.
     * See the note about byte order in this class description.
     * @return Address of the first byte.
     */
    public native int allocAndCopyBytes(byte[] data)
    throws NativeCallException;

    /** Allocates memory.
     *The JNI C function used the {@code malloc} function of the standard C library.
     * @param numberOfBytes Size of the allocated memory in bytes.
     * @return Address of the first byte.
     */    
    public native int allocBytes(int numberOfBytes)
    throws NativeCallException;
    
    /** Delete the allocated data.
     *The JNI C function used the {@code delete} function of the standard C library.
     */
    public native void deleteAllocatedData(int firstByteAddress)
    throws NativeCallException;

    /** Write maximal {@code max} bytes.
     *This is a secure version of {@link #writeBytes writeBytes}.
     *@throws NativeCallException if {@code bytes.length > max}.
     */
    public void writeBytesSecure(int firstByteAddress, byte[] bytes, int max)
    throws NativeCallException{
        if(bytes.length > max){
            throw new NativeCallException("max value "+max+"<"+ "bytes length "+bytes.length);
        }
        writeBytes(firstByteAddress, bytes);
    }
    
     /** Write bytes.*/
    public native void writeBytes(int firstByteAddress, byte[] bytes)
    throws NativeCallException;
    
}
