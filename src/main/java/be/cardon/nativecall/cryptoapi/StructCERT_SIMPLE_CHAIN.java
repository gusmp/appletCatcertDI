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

package be.cardon.nativecall.cryptoapi;

import be.cardon.nativecall.NativeBoolean;
import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.NativeInt;
import be.cardon.nativecall.NativeStructure;

/**Wrapper for structure {@code CERT_SIMPLE_CHAIN}.
 * 
 * @author Rodolphe
 */
public class StructCERT_SIMPLE_CHAIN extends NativeStructure{
    
    public final static Integer[] elementsSize  = {4,8,4,4,4,4,4};
    public static int lengthInBytes = 32;
    private static java.util.List<Integer> relAddresses = 
            new java.util.ArrayList<Integer>();
            
    
    /** Creates a new instance of the structure, new native structure. */
    public StructCERT_SIMPLE_CHAIN() throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses);
        this.setCbSize(this.getLength());
    }
    
    /** Creates a new instance of the structure, existing native structure. */
    public StructCERT_SIMPLE_CHAIN(int address) throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses, address);
        if(this.cbSize().get()<this.getLength()){
            throw new NativeCallException("Wrong structure size");
        }
    }

    /******************** MEMBERS FUNCTIONS*******************/
    
    public NativeInt cbSize()throws NativeCallException{
        boolean readOnly = true;
        return new NativeInt(this.getAddressOfElement(0),readOnly);
    }
    
    /**PRIVATE - set the CbSize.*/
    private void setCbSize(int cbSize) throws NativeCallException{
        LLC.writeInt(this.getAddressOfElement(0), cbSize);
    }
    
    public StructCERT_TRUST_STATUS TrustStatus() throws NativeCallException{
        return new StructCERT_TRUST_STATUS(this.getAddressOfElement(1));
    }
    
    public NativeInt cElement()throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(2));
    }
    
    /**return an address of a pointer to the CERT_CHAIN_ELEMENT (array).
     */
    public NativeInt rgpElement() throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(3));
    }
    
    /**pointer to CERT_TRUST_LIST_INFO.*/
    public NativeInt pTrustListInfo() throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(4));
    }
    
    public NativeBoolean fHasRevocationFreshnessTime() throws NativeCallException{
        return new NativeBoolean(this.getAddressOfElement(5));
    }

    public NativeInt dwRevocationFreshnessTime() throws NativeCallException{
        return new NativeInt(this.getAddressOfElement(6));
    }

    /******************** EXTENDED FUNCTIONS*******************/
    
    /*
    public StructArrayCERT_CHAIN_ELEMENT element() throws NativeCallException{
        int arrayAddress = LLC.readInt(this.rgpElement());
        int arrayLength = this.cElement();
        return new StructArrayCERT_CHAIN_ELEMENT(arrayAddress, arrayLength);
    }
     **/
    public StructCERT_CHAIN_ELEMENT[] element() throws NativeCallException{
        int arrayAddress = LLC.readInt(this.rgpElement().get());
        int arrayLength = this.cElement().get();
        int structSize = StructCERT_CHAIN_ELEMENT.lengthInBytes;
        StructCERT_CHAIN_ELEMENT[] ChainElemArray = new StructCERT_CHAIN_ELEMENT[arrayLength];
        int elemAddress;
        for(int it = 0; it < arrayLength ; it++){
            elemAddress = arrayAddress + it * structSize;
            ChainElemArray[it] = new StructCERT_CHAIN_ELEMENT(elemAddress);
        }
        return ChainElemArray;
    }
}

