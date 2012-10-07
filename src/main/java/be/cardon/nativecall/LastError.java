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

/**Wrapped class for {@code GetLastError} Windows API function.
 * <p>
 * This class is used in your <i>JNI</i> C or C++ code when a API function failed, 
 * returning {@code FALSE}. Your JNI code must call {@link #setLastError 
 * setLastError}.
 * </p>
 * <p>This class was created because the {@code GetLastError()} function must
 * be called in the same thread as that generated the error. But two calls to 
 * native function are made in separated thread. So the called to 
 * {@code GetLastError()} must be made directly in the exception handling 
 * function.
 * </p>
 * <p>The error number is documented in {@code WinError.h}. This file is 
 * available in the Microsoft Plateform SDK for Windows 2003 or other version.
 * The description of these errors with a particular function is documented in 
 * the MSDN library (online or distributed with SDK's).
 * </p>
 * 
 * @author Rodolphe
 */
public class LastError {
    
    /**Last error number (private).*/
    private static int err=0;
    
    /**Set the last error number.*/
    public static void setLastError(int errorNumber) {
        err = errorNumber;
    }
    
    /**Get the last error number.
     *Call the {@link #reset reset} method after reading the last error number.
     */
    public static int getLastError(){
        return err;
    }
    
    /**Get the last error number in decimal if {@code 0 < error < 13884}, 
     * otherwise in hexadecimal.
     */
    public static String getLastErrorHex(){
        if (err > 13884 | err < 0){
            return "0x"+Integer.toHexString(err);
        }else{
            return Integer.toString(err);
        }
    }    
    
    /**Reset the last error number to zero.*/
    public static void reset(){
        setLastError(0);
    }
}
