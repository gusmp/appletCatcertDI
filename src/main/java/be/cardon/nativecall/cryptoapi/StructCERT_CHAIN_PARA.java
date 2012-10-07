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

import be.cardon.nativecall.LowLevelCalls;
import be.cardon.nativecall.NativeBoolean;
import be.cardon.nativecall.NativeCallException;
import be.cardon.nativecall.NativeInt;
import be.cardon.nativecall.NativeStructure;


/**Wrapper for structure {@code CERT_CHAIN_PARA}.
 *<pre>
 *typedef struct _CERT_CHAIN_PARA {
 *  DWORD cbSize;
 *  CERT_USAGE_MATCH RequestedUsage;
 *  CERT_USAGE_MATCH RequestedIssuancePolicy; }
 *  DWORD dwUrlRetrievalTimeout;              } extra
 *  BOOL fCheckRevocationFreshnessTime;       } fields
 *  DWORD dwRevocationFreshnessTime;          }
 *} CERT_CHAIN_PARA, 
 **PCERT_CHAIN_PARA;
 *</pre>
 *Note : the {@code CERT_CHAIN_PARA_HAS_EXTRA_FIELDS} has been defined in
 *the JNI native code. So the extra fields are always available. 
 */
public class StructCERT_CHAIN_PARA extends NativeStructure{
    public static final Integer[] elementsSizeLong = {4, 12, 12, 4, 4, 4}; //extraFields = true
    public static final Integer[] elementsSizeShort = {4, 12};

    public static final int lengthInBytesLong = 40; //extraFields = true
    public static final int lengthInBytesShort = 16;
    
    private static java.util.List<Integer> relAddressesLong = 
            new java.util.ArrayList<Integer>();
    private static java.util.List<Integer> relAddressesShort = 
            new java.util.ArrayList<Integer>();

    
    private boolean extraFields;
    
    /**Creates a new instance of this class, new native object.*/
    public static StructCERT_CHAIN_PARA newInstance(boolean extraFields)throws NativeCallException{
        StructCERT_CHAIN_PARA certChainPara;
        if(extraFields){
            certChainPara = new StructCERT_CHAIN_PARA(
                    lengthInBytesLong,
                    elementsSizeLong,
                    relAddressesLong);
        }else{
            certChainPara = new StructCERT_CHAIN_PARA(
                    lengthInBytesShort,
                    elementsSizeShort,
                    relAddressesShort);
        }
        certChainPara.extraFields = extraFields; 
        return certChainPara;
    }
    
    /**Creates a new instance of this class, existing native object.
     *The native object may be a version with or without extra fields.
     */
    public static StructCERT_CHAIN_PARA newInstance(int address)throws NativeCallException{
        //check the address and read the first byte
        if(address==0){
              throw new NativeCallException("Address must be not null");
        }
        int cbSize = new LowLevelCalls().readInt(address);
        StructCERT_CHAIN_PARA certChainPara;
        if(cbSize==lengthInBytesShort){
            certChainPara = new StructCERT_CHAIN_PARA(
                    lengthInBytesShort,
                    elementsSizeShort, 
                    relAddressesShort,
                    address);
            certChainPara.extraFields = false;
            return certChainPara;
        }else if(cbSize>=lengthInBytesLong){
            certChainPara = new StructCERT_CHAIN_PARA(
                    lengthInBytesLong,
                    elementsSizeLong, 
                    relAddressesLong,
                    address);
            certChainPara.extraFields = true;
            return certChainPara;
        }else{
            throw new NativeCallException("Invalid structure : read cbSize ="+cbSize);
        }
    }
    
    /**PRIVATE - Creates a new instance of StructCERT_INFO, and allocates memory for the
     native structure */
    private StructCERT_CHAIN_PARA(int lengthInBytes, Integer[] elementsSize,
            java.util.List<Integer> relAddresses) throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses);
        this.setCbSize(this.getLength());
    }
    
    
    /**PRIVATE - Creates a new instance of StructCERT_INFO, with the given address of an 
     *existing native structure*/
    private StructCERT_CHAIN_PARA(int lengthInBytes, Integer[] elementsSize,
            java.util.List<Integer> relAddresses, int address) throws NativeCallException{
        super(lengthInBytes, elementsSize, relAddresses, address);
        
        //check CbSize
        int CbSize = this.CbSize().get();
        if(CbSize<this.getLength()){
            throw new NativeCallException("the given structure is not a short version of CERT_CHAIN_PARA");
        }
    }

    public boolean hasExtraFields(){
        return this.extraFields;
    }
    
    private void assertExtraFields() throws NativeCallException{
        if(!this.extraFields){
            throw new NativeCallException("The structure has no extra fields.");
        }
    }
 
    /******************** MEMBERS FUNCTIONS*******************/
    
    /**Returns the size of this structure in bytes (read only). */
    public NativeInt CbSize()throws NativeCallException{
        boolean readOnly = true;
        return new NativeInt(
                this.getAddressOfElement(0), 
                readOnly);  
    }

    /**PRIVATE. Sets the size of this structure in bytes.
     * Function only used for the creation of a new native object.
     */
    private void setCbSize(int cbSize)throws NativeCallException{
        LLC.writeInt(this.getAddressOfElement(0), cbSize);  
    }

    /**Returns the {@code CERT_USAGE_MATCH RequestedUsage} structure.*/
    public StructCERT_USAGE_MATCH RequestedUsage() throws NativeCallException{
        return new StructCERT_USAGE_MATCH(this.getAddressOfElement(1));  
    }

    /**Returns the {@code CERT_USAGE_MATCH RequestedIssuancePolicy} structure.
     @throws NativeCallException if the structure has no extra fields.
     */
    public StructCERT_USAGE_MATCH RequestedIssuancePolicy() throws NativeCallException{
        assertExtraFields();
        return new StructCERT_USAGE_MATCH(this.getAddressOfElement(2));  
    }

    /**Time before the revocation checking times out in milliseconds.
     *@throws NativeCallException if the structure has no extra fields.
     */
    public NativeInt dwUrlRetrievalTimeout()throws NativeCallException{
         assertExtraFields();
         return new NativeInt(this.getAddressOfElement(3));
    }

   /**When this flag is {@code TRUE}, an attempt is made to retrieve a new CRL if 
     * ThisUpdate is greater than or equal to Current Time minus 
     * {@code dwRevocationFreshnessTime}. If this flag is not set, the CRL's NextUpdate 
     * time is used. 
    *@throws NativeCallException if the structure has no extra fields.
     */
    public NativeBoolean fCheckRevocationFreshnessTime() throws NativeCallException{
        assertExtraFields();
        return new NativeBoolean(this.getAddressOfElement(4));
    }

    /**Largest CurrentTime, in seconds, minus the CRL's ThisUpdate of all 
     * elements checked. 
     *@throws NativeCallException if the structure has no extra fields.
     */
    public NativeInt dwRevocationFreshnessTime()throws NativeCallException{
        assertExtraFields();        
        return new NativeInt(this.getAddressOfElement(5));
    }

    /******************** EXTENDED FUNCTIONS*******************/
    
    //no functions defined
    
}