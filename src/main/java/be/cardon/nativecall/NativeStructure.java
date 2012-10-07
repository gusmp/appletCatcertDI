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

import java.util.List;
/**Wrapper for a native structure.
 * @author Rodolphe
 */
public abstract class NativeStructure extends NativeObject{

    private Integer[] elementsSize;
    private List<Integer> relAddresses;

    public NativeStructure(int lengthInBytes, Integer[] elementsSize, List<Integer> relAddresses) throws NativeCallException{
        super(lengthInBytes);
        this.elementsSize = elementsSize;
        this.initStruct(relAddresses);
   }
    public NativeStructure(int lengthInBytes, Integer[] elementsSize, List<Integer> relAddresses, int address) throws NativeCallException{
        super(lengthInBytes, address);
        this.elementsSize = elementsSize;
        this.initStruct(relAddresses);
    }
    
     protected final void initStruct(List<Integer> relAddresses) throws NativeCallException{
        if(relAddresses.isEmpty()){
             this.checkStructSize();
             this.getRelativeAddress(relAddresses);
        }else{
        }
        this.relAddresses = relAddresses;
    }

    protected final void checkStructSize() throws NativeCallException{
        if(IntegerArraySum(elementsSize)!= this.getLength()){
            throw new NativeCallException("Invalid Structure Class : sum(size of elements) != total size ");
        }
    }
    
    private final int IntegerArraySum(Integer[] IntegerArray){
        int result=0;
        for(int j=0;j<IntegerArray.length;j++){
            result += IntegerArray[j];
        }
        return result;
    }
    
    /**the first index is zero !*/
    public final int getAddressOfElement(int elementIndex){
        int addressOfElement = this.getAddress()+ this.relAddresses.get(elementIndex);
        return addressOfElement;
    }
    
    public final NativeObject getNativeObjectElement(int elementIndex) throws NativeCallException{
        int addressOfElement = getAddressOfElement(elementIndex);
        int sizeOfElement = elementsSize[elementIndex];
        return new NativeObject(sizeOfElement, addressOfElement);
    }

    protected final void getRelativeAddress(List<Integer> relAddress){
        int numberOfElements = elementsSize.length;
        relAddress.add(new Integer(0));
        int temp = 0;
        for(int i=0; i<numberOfElements-1; i++){
            relAddress.add(new Integer(temp += elementsSize[i]));
        }
    }
 }
