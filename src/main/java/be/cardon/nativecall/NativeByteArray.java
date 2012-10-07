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

/** Wrapped class for native {@code char, char[]} type.
 * Class with read only support.
 * @author Rodolphe
 */
public class NativeByteArray extends NativeObject{
    
    /** allocates a new byte array */
    public NativeByteArray(int LengthInBytes) throws NativeCallException {
        super(LengthInBytes);
    }
    
    /** existing byte array.*/
    public NativeByteArray(int LengthInBytes, int address) throws NativeCallException{
        super(LengthInBytes, address);
    }

   /** Convert a NativeObject in a NativeByteArray.*/
    public static NativeByteArray newInstance(NativeObject obj) throws NativeCallException{
        int address = obj.getAddress();
        int size = obj.getLength();
        return new NativeByteArray(size, address);
    }
    
    /** existing byte array, with protection or not.*/
    public NativeByteArray(int LengthInBytes, int address, boolean readOnly)
    throws NativeCallException{
        super(LengthInBytes, address);
        super.setReadOnly(readOnly);
    }    
    
    /** return the whole buffer content.*/
    public byte[] read() throws NativeCallException{
        return new LowLevelCalls().readBytes(this.getAddress(), this.getLength());
    }

    /** return the bytes, beginning at the given offset, and with the given 
     * length.*/
    public byte[] read(int offset, int len) throws NativeCallException{
        if(offset+len > this.getAddress()+this.getLength()){
            throw new NativeCallException("Memory access exception : offset or len to big");
        }
        return new LowLevelCalls().readBytes(this.getAddress()+offset, len);
    }
    /** write the given byte array in the buffer. (length of data may be < buffer length)*/
    public void write(byte[] data, int offset) throws NativeCallException{
        if(offset+data.length>this.getAddress()+this.getLength()){
            throw new NativeCallException("Data too big");
        }
        new LowLevelCalls().writeBytes(this.getAddress(), data);
    }   
    /** write the given byte in the buffer.*/
    public void write(byte[] data) throws NativeCallException{
        int offset=0;
        write(data, offset);
    }   
}
