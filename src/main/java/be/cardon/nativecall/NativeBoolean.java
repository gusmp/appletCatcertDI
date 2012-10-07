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

    
/** Wrapped class for native {@code bool} type.
 * Note that the length definition is ambiguous (the effective memory
 * length varies).
 * Class with read only support.
 * @author Rodolphe
 */
public class NativeBoolean extends NativeObject{

    /**The allocated memory is not always equal to this valuen but it doesn't 
     * matter (LengthInBytes is only used for allocation and must be >=1) !*/
    public static final int LengthInBytes = 4; 
    
    /** allocates a new boolean */
    public NativeBoolean() throws NativeCallException {
        super(LengthInBytes);
    }
    
    /** existing boolean.*/
    public NativeBoolean(int address) throws NativeCallException{
        super(LengthInBytes, address);
    }
    
    /** Convert a NativeObject in a NativeBoolean. The size of the native object 
     must be <= 4.*/
    public static NativeBoolean newInstance(NativeObject obj) throws NativeCallException{
        int address = obj.getAddress();
        int size = obj.getLength();
        if(size > 4){
            throw new NativeCallException(
                    "The size of the given object (" + size +
                    ") doesn't match the required size (<5)"  
                    );
        }
        return new NativeBoolean(address);
    }
    
    /** existing boolean, with protection or not.*/
    public NativeBoolean(int address, boolean readOnly) throws NativeCallException{
        super(LengthInBytes, address);
        super.setReadOnly(readOnly);
    }    
    
    /** return the native {@code bool} value.*/
    public boolean get() throws NativeCallException{
        return new LowLevelCalls().readBoolean(this.getAddress());
    }

    /** set the native {@code bool} value.*/
    public void set(boolean value) throws NativeCallException{
        if(this.isReadOnly()){
            throw new NativeCallException("Native boolean is read only");
        }
        new LowLevelCalls().writeBoolean(this.getAddress(), value);
    }        
}
