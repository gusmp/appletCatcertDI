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

 * NativeObject.java
 *
 * NativeObject wrapper 
 *
 * => used with new object (allocation and auto garbage collector with Java)
 * => or used with existing object
 */

package be.cardon.nativecall;

import be.cardon.utils.Debug;


/**Super class for wrapped native objects.
 * <p>
 * {@code NativeObject}s are linked to existing native objects or new native 
 * object. Later objects are allocated automatically when the new instance of 
 * {@code NativeObject} is called and automatically freed with the Java garbage
 * collector. Each {@code NativeObject} or inherited class has an address (see
 * {@link #getAddress getAddress}) and a size (see {@link #getLength getLength}). 
 * </p>
 * <p>This class help you to avoid a {@code MEMORY ACCESS VIOLATION} error : you
 * can't create a {@code NativeObject} that has a null address.
 * </p>
 */
public class NativeObject {
    
    public static int BYTE_SIZE = 1;
    public static int INT_SIZE = 4;
    
    private int address;
    private int lengthInBytes;
    
    /**readOnly when 'set' is prohibited*/
    private boolean readOnly=false;
    
    protected LowLevelCalls LLC = new LowLevelCalls();
    private boolean allocByJava;
    
    /** Creates a new instance of NativeObject, allocates memory for a new native 
     * object, with the given size in bytes.*/
     /** Creates a new instance of NativeObject, and manages the allocation and 
      * desallocation of a new native object.
      * 
      * <p>
      * The native object is freed when the java {@code NativeObject} is freed
      * with the garbage collector. 
      * </p>
      *
      * @param lengthInBytes Size of the allocated memory in bytes.
      * @throws NativeCallException if {@code lengthInBytes} is null or if the
      * memory allocation failed.
      */
    
    public NativeObject(int lengthInBytes) throws NativeCallException{

        if(lengthInBytes==0){
            throw new NativeCallException("NativeObject : lengthInBytes must be non null");
        }
        
        //allocation
        this.address = LLC.allocBytes(lengthInBytes);
        if(this.address==0){
            throw new NativeCallException("NativeObject : memory allocation failed");
        }
        this.allocByJava = true;
        this.lengthInBytes = lengthInBytes;
    }
 
     /** Creates a new instance of NativeObject associated to an existing native 
      * object.
      *
      * <p>
      * The native object is <b>not</b> freed when the java {@code NativeObject} is freed
      * with the garbage collector. The native object must be freed door other 
      * means (see the 
      * {@link LowLevelCalls#deleteAllocatedData deleteAllocatedData} 
      * function).
      * </p>
      *
      * @param lengthInBytes Size of the allocated memory in bytes.
      * @param address Address of the first byte in memory.
      * @throws NativeCallException if {@code address} is null, or if  
      * {@code lengthInBytes} is null.
      */
    public NativeObject(int lengthInBytes, int address) throws NativeCallException {
        //no allocation
        if(address==0){
            throw new NativeCallException("NativeObject : address must be non zero");
        }
        if(lengthInBytes==0){
            throw new NativeCallException("NativeObject : lengthInBytes must be non null");
        }        
        this.address = address;
        this.allocByJava = false;
        this.lengthInBytes = lengthInBytes;
    }
    
    /**Deletes this object and if needed the associated native object.
     * <p>Deletes the wrapped native object if this java {@code NativeObject} was 
     * created with {link #NativeObject.NativeObject(int)}.<p>
     * <p><b>This function is called door the garbage collector. You should not 
     * call this function yourself.</b>
     * </p>
     */
    public void finalize() throws java.lang.Throwable
    {
        if(this.allocByJava){
            Debug.println("Finalize  : frees native object with address = "+address);
            LLC.deleteAllocatedData(address);
        }
            super.finalize();
    }
    /**Returns the native object length the in bytes.*/
    public int getLength(){
        return this.lengthInBytes;
    }
    
    /**Returns the native object address in memory.*/
    public int getAddress(){
        return this.address;
    }
    
    protected void setReadOnly(boolean readOnly){
        this.readOnly = readOnly;
    }
    
    /**Returns true if this native object may (should) not be modified.
     *This super class don't protects effectively the data. The protection
     *must be implemented in herited classes if needed.
     *By default, the native object is not readOnly.
     */
    public boolean isReadOnly(){
        return readOnly;
    }
}
