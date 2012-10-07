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

/** Wrapped class for native {@code int} type.
 * Class with read only support.
 * @author Rodolphe
 */
public class NativeInt extends NativeObject{
    
    public final static int LengthInBytes = 4;
    
    /** allocates a new integer */
    public NativeInt() throws NativeCallException {
        super(LengthInBytes);
    }
    
    /** existing integer.*/
    public NativeInt(int address) throws NativeCallException{
        super(LengthInBytes, address);
    }
    
    /** Convert a NativeObject in a nativeInt. The size of the native object 
     must match the size of NativeInt.*/
    public static NativeInt newInstance(NativeObject obj) throws NativeCallException{
        int address = obj.getAddress();
        int size = obj.getLength();
        if(size != LengthInBytes){
            throw new NativeCallException(
                    "The size of the given object (" + size +
                    ") doesn't match the required size (" + LengthInBytes +")"  
                    );
        }
        return new NativeInt(address);
    }
    
    /** existing integer, with protection or not.*/
    public NativeInt(int address, boolean readOnly) throws NativeCallException{
        super(LengthInBytes, address);
        super.setReadOnly(readOnly);
    }    
    
    /** return the native {@code int} value.*/
    public int get() throws NativeCallException{
        return new LowLevelCalls().readInt(this.getAddress());
    }

    /** set the native {@code int} value.*/
    public void set(int value) throws NativeCallException{
        if(this.isReadOnly()){
            throw new NativeCallException("Native integer is read only");
        }
        new LowLevelCalls().writeInt(this.getAddress(), value);
    }    
    
}
