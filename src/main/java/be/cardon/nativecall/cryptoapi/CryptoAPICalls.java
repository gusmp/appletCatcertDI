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

 * ms-help://MS.MSDNQTR.v80.en/MS.MSDN.v80/MS.WIN32COM.v10.en/seccrypto/security/cryptography_functions.htm
 */

package be.cardon.nativecall.cryptoapi;


/**Native functions calls to CryptoAPI using the Java Native Interface (JNI).
 *<p>The native functions are a set of the CryptoAPI functions. See the MSDN
 *documentation to know exactely the meaning of the arguments and the error
 *failure.</p>
 *<p><b>Note 1 :</b>
 *A lot of CryptoAPI function returns {@code FALSE} in case of error, and 
 *a call to {@code GetLastError()} in the same thread returns the Windows last error
 *defined in {@code WinError.h}. The functions of this class don't return a boolean
 *but throw a {@link CryptoAPIException CryptoAPIException}.
 *Call the static method {@link be.cardon.nativecall.LastError#getLastError} to
 *get the Windows last error number.</p>
 *<p><b>Note 2 :</b>
 *Some CryptoAPI function return a potentially large amount of data to an 
 *address provided as one of the parameters by the application (see MSDN article
 *"Retrieving Data of Unknown Length"). This JNI implementation already called 
 *two times these functions : the first call retrieves the data length, a memory
 *allocation is done and the second call retrieves the data.</p>
 * @author CARDON DE LICHTBUER Rodolphe
 * Juli 2006
 */
public class CryptoAPICalls {
    
    private static boolean _initialized = false;
    
    /** Creates a new instance of CryptoAPICalls */
    public CryptoAPICalls() throws CryptoAPIException{
        if(_initialized){
            return;
        }
        if(!be.cardon.utils.OperatingSystem.isWindows()){
            throw new CryptoAPIException("CryptoAPICalls only available on Windows.");
        }
        try{
        be.cardon.utils.LibraryLoader.loadLib("cryptoapi4java.dll");
       _initialized = true;
        }catch(Exception e){
            throw new CryptoAPIException(e);
        }
    }

    /** Acquires a handle to the current user's key container within a particular CSP.
     * <p>Wrapped function :</p>
     * <pre>
     * BOOL WINAPI CryptAcquireContext(
     * HCRYPTPROV* phProv,   [OUT] 
     * LPCTSTR pszContainer, [IN]
     * LPCTSTR pszProvider,  [IN]
     * DWORD dwProvType,     [IN]
     * DWORD dwFlags         [IN]
     *    );
     *</pre>
     *Implemented as <code>CryptAcquireContextW</code> (unicode).
     *
     *@param containerName container name
     *@param providerName provider name
     *@param dwProvType Specifies the type of provider to acquire
     *@param dwFlags Flag values. This parameter is usually set to zero, 
     * but some applications set one or more of the following flags.
     *@throws CryptoAPIException
     *@return Handle of a CSP. When you have finished using 
     * the CSP, release the handle by calling the 
     * {@link #CryptReleaseContext CryptReleaseContext} function. 
     */
     public native int CryptAcquireContextW(
             String containerName, 
             String providerName, 
             int dwProvType,
             int dwFlags) throws CryptoAPIException;

     
     
     /** Releases the handle acquired by the {@link #CryptAcquireContextW CryptAcquireContextW} function.
      * <p>Wrapped function:</p>
      * <pre>
      * BOOL WINAPI CryptReleaseContext(
      * HCRYPTPROV hProv  [IN]
      * DWORD dwFlags     [IN] (Reserved for future use and must be zero)
      * );
      * </pre>
      *@param hProv Handle of a cryptographic service provider (CSP) created by 
      *             a call to 
      * {@link #CryptAcquireContextW(java.lang.String,java.lang.String,int,int) 
      * CryptAcquireContextW}. 
      */
      public native void CryptReleaseContext(
              int hProv) throws CryptoAPIException;
     
      
      
      /** Gets a handle to the key exchange or signature key.
       * <p>Wrapped function:</p> 
       * <pre>       
       * BOOL CryptGetUserKey(
       * HCRYPTPROV hProv,     [IN]
       * DWORD dwKeySpec,      [IN]
       * HCRYPTKEY* phUserKey  [OUT]
       * );
       * </pre>
       *@param hProv <code>HCRYPTPROV </code>handle of a cryptographic service provider (CSP) 
       * created by a call to {@link #CryptAcquireContextW CryptAcquireContextW}.
       *@param dwKeySpec Identifies the private key to use from the key 
       * container. It can be <code>AT_KEYEXCHANGE</code> or <code>AT_SIGNATURE
       * </code>. Additionally, some providers allow access to other 
       * user-specific keys through this function. For details, see the 
       * documentation on the specific provider.
       *@return <code>HCRYPTKEY</code> handle of the retrieved keys. When you have finished 
       * using the key, delete the handle by calling the 
       * {@link #CryptDestroyKey CryptDestroyKey} function. 
       */
      public native int CryptGetUserKey(
              int hProv, 
              int dwKeySpec) throws CryptoAPIException;

      
      
      /** Destroys a key.
       *<p>Wrapped function:</p> 
       * <pre>
       *   BOOL CryptDestroyKey(
       *   HCRYPTKEY hKey    in
       * );
       * </pre>
       *@param hKey Handle of the key to be destroyed. 
       */
      public native void CryptDestroyKey(
              int hKey) throws CryptoAPIException;
      
      
      
      
      /**Retrieves data that governs the operations of a key.
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL CryptGetKeyParam(
       *HCRYPTKEY hKey,
       *DWORD dwParam,
       *BYTE* pbData,
       *DWORD* pdwDataLen,
       *DWORD dwFlags,  (No flags are currently defined.)
       *);
       *</pre>
       *@param hKey Handle to the key being queried.
       *@param dwParam Specifies the query being made. See MSDN documentation.
       *@return The form of the returned data depends on the value of dwParam. 
       */
      public native byte[] CryptGetKeyParam(
              int hKey, 
              int dwParam)throws CryptoAPIException;
      
      
      
      
      /** Decrypts a section of ciphertext by using the specified encryption key.
       *<p>Wrapped function:</p> 
       *<pre>
       * BOOL WINAPI CryptDecrypt(
       * HCRYPTKEY hKey,   IN  Handle to the key to use for the decryption. 
       *    An application obtains this handle by using either the CryptGenKey or CryptImportKey function. 
       * HCRYPTHASH hHash, IN
       * BOOL Final,       IN
       * DWORD dwFlags,    IN
       * BYTE* pbData,     IN/OUT 
       * DWORD* pdwDataLen IN/OUT 
       *  );
       *</pre>
       *@param hKey  Handle to the key to use for the decryption. An application 
       * obtains this handle by using either the CryptGenKey or CryptImportKey 
       * function. This key specifies the decryption algorithm to be used.
       *@param hHash Handle to a hash object. If data is to be decrypted and 
       * hashed simultaneously, a handle to a hash object is passed in this 
       * parameter. The hash value is updated with the decrypted plaintext. 
       * This option is useful when simultaneously decrypting and verifying a 
       * signature. Before calling CryptDecrypt, the application must obtain a 
       * handle to the hash object by calling the 
       * {@link #CryptCreateHash CryptCreateHash} function. 
       * After the decryption is complete, the hash value can be obtained through 
       * {@link #CryptGetHashParam CryptGetHashParam}, it can be signed using 
       * CryptSignHash, or it can be used to verify a digital signature using 
       * CryptVerifySignature. If no hash is to be done, this parameter must be zero.
       *@param Final Specifies whether this is the last section in a series 
       * being decrypted. This value is TRUE if this is the last or only block. 
       * If this is not the last block, this value is FALSE.
       *@param dwFlags Defined flags : <code>CRYPT_OAEP</code>.
       *@param data Data to be decrypted
       *@return Byte array with the decrypted data (plain text).
       */
      public native byte[] CryptDecrypt(
              int hKey, 
              int hHash, 
              boolean Final, 
              int dwFlags, 
              byte[] data) throws CryptoAPIException;
     
      
      
      
      /**Encrypts data.
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CryptEncrypt(
       *  HCRYPTKEY hKey,   [in] Handle to the encryption key
       *  HCRYPTHASH hHash, [in] If data is to be hashed and encrypted simultaneously, a handle to a hash object can be passed in the hHash parameter. 
       *  BOOL Final,      [in] Boolean value that specifies whether this is the last section in a series being encrypted.
       *  DWORD dwFlags,  [in] The following dwFlags =CRYPT_OAEP
       *  BYTE* pbData,   [in, out] Pointer to a buffer that contains the data to be encrypted => IN ONLY
       *  DWORD* pdwDataLen,  [in, out] Pointer to a DWORD value that contains the length of the data buffer = IN ONLY
       *  DWORD dwBufLen  [in] DWORD value that specifies the length, in bytes, of the input pbData buffer => must be large enough, depending on the algorithm used.
       * );
       *<pre>
       */
      public native byte[] CryptEncrypt(
              int hKey, 
              int hHash, 
              boolean Final, 
              int dwFlags, 
              byte[] data, 
              int bufferSizeForOutput) throws CryptoAPIException;
      
      
      
      
      /**Creates an empty hash object.
       *<p>Wrapped function:</p> 
       *<pre>
       * BOOL WINAPI CryptCreateHash(
       * HCRYPTPROV hProv,  [in] Handle of a cryptographic service provider (CSP) created by a call to CryptAcquireContext. 
       * ALG_ID Algid, [in] ALG_ID that identifies the hash algorithm to use.
       * HCRYPTKEY hKey,  [in] If the type of hash algorithm is a keyed hash, such as the HMAC or Message Authentication Code (MAC) algorithm
       *    For nonkeyed algorithms, this parameter must be set to zero.
       * DWORD dwFlags, [in] Reserved for future use and must be zero. ==> DELETED !
       * HCRYPTHASH* phHash [out] Address to which the function copies a handle to the new hash object. => returns the handle
       * );
       *</pre>
       *When you have finished using the hash object, release the handle by calling the CryptDestroyHash function. 
       */
      public native int CryptCreateHash(
              int hProv, 
              int Algid, 
              int hKey)  throws CryptoAPIException;
      
      /**Destroys an hash object.
       *BOOL WINAPI CryptDestroyHash(
        HCRYPTHASH hHash
        );
      */
      public native void CryptDestroyHash(
              int hHash)  throws CryptoAPIException;
      
      /**Adds data to a specified hash object.
       *<p>Wrapped function:</p> 
       *<pre>
       * BOOL WINAPI CryptHashData(
       * HCRYPTHASH hHash, IN
       * BYTE* pbData,     IN
       * DWORD dwDataLen,  IN
       * DWORD dwFlags     IN
       * );
       *</pre>
       */
      public native void CryptHashData(
              int hHash,
              byte[] data,
              int dwFlags) throws CryptoAPIException;
      
      
      
      /**Signs the specified hash object. 
       *<p>The signature returned is in <b>little endian</b> ! You must reverse 
       * the bytes to <b>big endian</b></p>
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CryptSignHash(
       *HCRYPTHASH hHash, [in] Handle of the hash object to be signed
       *DWORD dwKeySpec, [in] Identifies the private key to use from the provider's container :AT_KEYEXCHANGE or AT_SIGNATURE
       *LPCTSTR sDescription, [in]This parameter is no longer used and must be set to NULL to prevent security vulnerabilities. =>DELETED!
       *DWORD dwFlags, : CRYPT_NOHASHOID, CRYPT_X931_FORMAT
       *BYTE* pbSignature, [out] Pointer to a buffer receiving the signature data => RETURN VALUE
       *DWORD* pdwSigLen [in, out] Pointer to a DWORD value that specifies the size, in bytes, of the pbSignature buffer.
       *);
       *<pre>
       * When the function returns, the DWORD value contains the number of bytes stored in the buffer.  => IN ONLY
       */
      public native byte[] CryptSignHash(
              int hHash, 
              int dwKeySpec, 
              int dwFlags) throws CryptoAPIException;

      
      
      
     /**Sets a hash object parameter.
      *<p>Wrapped function:</p> 
      *<pre>
      *BOOL WINAPI CryptSetHashParam(
      *HCRYPTHASH hHash, [in] A handle to the hash object on which to set parameters. 
      *DWORD dwParam, [in]
      *BYTE* pbData, [in] A value data buffer
      *DWORD dwFlags [in] This parameter is reserved for future use and must be set to zero.  => DELETED
      *);
      *</pre>
      */
      public native byte[] CryptSetHashParam(
              int hHash, 
              int dwParam, 
              byte[] Data) throws CryptoAPIException;
      
      /**Retuns the requested hash parameter.
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CryptGetHashParam(
       *HCRYPTHASH hHash, [in] Handle of the hash object to be queried. 
       *DWORD dwParam, [in] Query type. This parameter can be set to one of the following queries. 
       *BYTE* pbData, [out] Pointer to a buffer that receives the specified value data. => RETURN VALUE
       *DWORD* pdwDataLen, [in, out] Pointer to a DWORD value specifying the size, in bytes, of the pbData buffer.
       *DWORD dwFlags [in] Reserved for future use and must be zero. => DELETED
       *);
       *</pre>
       */
      public native byte[] CryptGetHashParam(
              int hHash, 
              int dwParam) throws CryptoAPIException;
      
      
      
 /*  **********************************************************************
  *
  * CERT
  *
  *
  */
     /**Closes a certificate store handle.
      *<p>Wrapped function:</p> 
      *<pre>
      *BOOL WINAPI CertCloseStore(
      *HCERTSTORE hCertStore, [in] Handle of the certificate store to be closed. 
      * DWORD dwFlags [in] Typically, this parameter uses the default value zero. 
      * The default is to close the store with memory remaining allocated for contexts 
      * that have not been freed. In this case, no check is made to determine whether memory 
      * for contexts remains allocated. 
      *);
      *</pre>
      */
      public native void CertCloseStore(
              int hCertStore, 
              int dwFlags) throws CryptoAPIException;
      
      
      
      /**Retrieves the first or next certificate in a certificate store.
       *<p>Wrapped function:</p> 
       *<pre>
       *PCCERT_CONTEXT WINAPI CertEnumCertificatesInStore(
       *HCERTSTORE hCertStore, [in] Handle of a certificate store
       *PCCERT_CONTEXT pPrevCertContext [in] Pointer to the CERT_CONTEXT of the previous certificate context found.
       *);
       *</pre>
       */
      public native int CertEnumCertificatesInStore(
              int hCertStore, 
              int pPrevCertContext) throws CryptoAPIException;
      
      
      
      
      
      /**Duplicates a certificate 
       * context by incrementing its reference count.
       *<p>Wrapped function:</p>
       *<pre>
       *PCCERT_CONTEXT WINAPI CertDuplicateCertificateContext(
       *PCCERT_CONTEXT pCertContext
       *);
       *</pre>
       */
      public native int CertDuplicateCertificateContext(int pCertContext) throws CryptoAPIException;
      

      /**Opens a certificate store using a specified store provider type.
       *<p>Wrapped function:</p>
       *<pre> 
       *HCERTSTORE WINAPI CertOpenStore(
       *LPCSTR lpszStoreProvider, [in] Specifies the store provider type : CERT_STORE_PROV_SYSTEM...
       *DWORD dwMsgAndCertEncodingType, [in]
       *HCRYPTPROV hCryptProv, [in]
       *DWORD dwFlags, [in]
       *const void* pvPara [in]
       *);
       *</pre>
       */
      public native int CertOpenStore(
              int lpszStoreProvider,
              int dwMsgAndCertEncodingType, 
              int hCryptProv, 
              int dwFlags, 
              int pvPara)throws CryptoAPIException;
      

      
      
      /**Frees a certificate context by decrementing its reference count.
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CertFreeCertificateContext(
       *PCCERT_CONTEXT pCertContext [in] Pointer to the CERT_CONTEXT to be freed. 
       *);
       *</pre>
       */
      public native void CertFreeCertificateContext(
              int pCertContext) throws CryptoAPIException;

      
      
      /**Obtains the subject or issuer name from 
       * a certificate {@code CERT_CONTEXT} structure and converts it to a null-terminated
       * character string.
       *Implemented as CertGetNameStringW (Unicode) and CertGetNameStringA (ANSI).
       *<p>Wrapped function:</p> 
       *<pre>
       *DWORD WINAPI CertGetNameString(
       *PCCERT_CONTEXT pCertContext, in
       *DWORD dwType, in
       *DWORD dwFlags, in
       *void* pvTypePara, in
       *LPTSTR pszNameString, [out] Pointer to an allocated buffer to receive the returned string
       *DWORD cchNameString [in] Size, in characters, allocated for the returned string
       *);
       *</pre>
       */
      public native String CertGetNameStringW(
              int pCertContext, 
              int dwType, 
              int dwFlags,
              int TypePara) throws CryptoAPIException;
      
      
      
      /**Checks the revocation status of the 
       * certificates contained in the {@code rgpvContext} array.
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CertVerifyRevocation(
       *DWORD dwEncodingType,
       *DWORD dwRevType,
       *DWORD cContext,
       *PVOID rgpvContext[],
       *DWORD dwFlags,
       *PCERT_REVOCATION_PARA pRevPara, [in optional]
       *PCERT_REVOCATION_STATUS pRevStatus [in out]
       *);
       */
      public native void CertVerifyRevocation(
              int dwEncodingType,
              int dwRevType,
              int cContext,
              int rgpvContext,
              int dwFlags,
              int pRevPara,
              int pRevStatus) throws CryptoAPIException;
    
      /**Acquires a {@code HCRYPTPROV} 
       * cryptographic service provider (CSP) handle including access to its 
       * related key container and the dwKeySpec for a user's specified 
       * certificate context.
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CryptAcquireCertificatePrivateKey(
       *PCCERT_CONTEXT pCert,
       *DWORD dwFlags,
       *void* pvReserved, (Reserved for future use and must be NULL.)
       *HCRYPTPROV* phCryptProv,
       *DWORD* pdwKeySpec,
       *   to use from the acquired provider's key container. It can be 
       *   AT_KEYEXCHANGE or AT_SIGNATURE. 
       *BOOL* pfCallerFreeProv [out] Pointer to a BOOL flag. => INDEX 2
       *);
       *</pre>
       *@param pCert Handle to a {@code CERT_CONTEXT}.
       *@param dwFlags Flags.
       *@return an array of two integers : 
       * <li>[0] the first integer {@code phCryptProv} is a pointer to the 
       * {@code HCRYPTPROV} handle.</li>
       * <li>[1] the second integer {@code pdwKeySpec} is a pointer to a {@code DWORD}
       * value identifying the private key.</li> 
       *</pre>
       */
      
      public native int[] CryptAcquireCertificatePrivateKey(
              int pCert, 
              int dwFlags)throws CryptoAPIException;


      /**Retrieves parameters that govern the 
       * operations of a cryptographic service provider (CSP).
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CryptGetProvParam(
       *HCRYPTPROV hProv,
       *DWORD dwParam,
       *BYTE* pbData, [out] Pointer to a buffer to receive the data
       *DWORD* pdwDataLen, [in, out] Pointer to a DWORD value specifying the size, in 
       * bytes, of the buffer pointed to by the pbData parameter. When the function 
       * returns, the DWORD value contains the number of bytes stored or to be stored in the buffer. 
       *DWORD dwFlags
       *);
       *</pre>
       */
      public native byte[] CryptGetProvParam(
              int hProv, 
              int dwParam,
              int dwFlags) throws CryptoAPIException;
      
      /**Customizes the operations of a cryptographic service provider (CSP). 
       *<p>Wrapped function:</p>
       *<pre>
       *BOOL WINAPI CryptSetProvParam(
       *  HCRYPTPROV hProv,   IN
       *  DWORD dwParam,      IN
       *  const BYTE* pbData, IN
       *  DWORD dwFlags       IN
       *  );
       *@param hProv The handle of a CSP for which to set values.
       *@param dwParam Specifies the parameter to set (see MSDN)
       *@param pbData A pointer to a data buffer that contains 
       * the value to be set as a provider parameter.
       *@param dwFlags optional flags.
       *@throws CryptoAPIException if the native function returns false (see MSDN).
       */
      public native void CryptSetProvParam(
              int hProv,
              int dwParam,
              int pbData,
              int dwFlags)throws CryptoAPIException;
      
      /**retrieves the information contained in an extended property of a 
       * certificate context.
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CertGetCertificateContextProperty(
       *PCCERT_CONTEXT pCertContext,
       *DWORD dwPropId,
       *void* pvData,  [out] A pointer to a buffer to receive the data as determined by dwPropId
       *DWORD* pcbData [in, out] A pointer to a DWORD value that specifies the size, 
       * in bytes, of the buffer pointed to by the pvData parameter. When the
       * function returns, the DWORD value contains the number of bytes to be 
       * stored in the buffer.
       *);
       *<pre>
       */
      public native byte[] CertGetCertificateContextProperty(
              int pCertContext, 
              int dwPropId) throws CryptoAPIException;     

     /**retrieves the PKI object from a location specified by a URL.
       *<p>Wrapped function:</p> 
       *<pre>
       *BOOL WINAPI CryptRetrieveObjectByUrl(
       *LPCTSTR pszUrl,
       *LPCSTR pszObjectOid,
       *DWORD dwRetrievalFlags,
       *DWORD dwTimeout,
       *LPVOID* ppvObject, [out] Pointer to a pointer to the returned object. 
       *HCRYPTASYNC hAsyncRetrieve, => NULL (deleted)
       *PCRYPT_CREDENTIALS pCredentials, [in, optional] 
       *LPVOID pvVerify, [in, optional]
       *PCRYPT_RETRIEVE_AUX_INFO pAuxInfo
       *);
       *</pre>
       */
    public native int CryptRetrieveObjectByUrlW(
            String Url, 
            String ObjectOid, 
            int dwRetrievalFlags,
            int dwTimeout,
            int pCredentials,
            int pvVerify,
            int pAuxInfo) throws CryptoAPIException;

    
    
    
    /**Converts an encoded name in a {@code CERT_NAME_BLOB}
     * structure to a null-terminated character string.
     *<p>Wrapped function:</p> 
     *<pre>
     *DWORD WINAPI CertNameToStr(
     *DWORD dwCertEncodingType,
     *PCERT_NAME_BLOB pName,
     *DWORD dwStrType,
     *LPTSTR psz,
     *DWORD csz
     *);
     *</pre>
     */
    public native String CertNameToStrW(int dwCertEncodingType, int pName, int dwStrType) throws CryptoAPIException;
    
    /**Builds a certificate chain context starting from an end certificate and 
     * going back, if possible, to a trusted root certificate.
     *<p>Wrapped function:</p> 
     *<pre>
     *BOOL WINAPI CertGetCertificateChain(
     *HCERTCHAINENGINE hChainEngine,
     *PCCERT_CONTEXT pCertContext,
     *LPFILETIME pTime,
     *HCERTSTORE hAdditionalStore,
     *PCERT_CHAIN_PARA pChainPara,
     *DWORD dwFlags,
     *LPVOID pvReserved, (Reserved parameter and must be NULL.)
     *PCCERT_CHAIN_CONTEXT* ppChainContext
     *);
     *</pre>
     *@param hChainEngine Handle of the chain engine (name space and cache) to 
     * be used. If hChainEngine is NULL, the default chain engine, 
     * {@code HCCE_CURRENT_USER}, is used. Can be set to 
     * {@code HCCE_LOCAL_MACHINE}. 
     *@param pCertContext Pointer to the {@code CERT_CONTEXT} of the end certificate, 
     * the certificate for which a chain is being built. This certificate context 
     * will be the zero-index element in the first simple chain. 
     *@param pTime Pointer to a {@code FILETIME} variable that indicates the time for 
     * which the chain is to be validated. Note that the time does not affect 
     * trust list, revocation, or root store checking. The current system time 
     * is used if {@code NULL} is passed to this parameter.
     *@param hAdditionalStore Handle of any additional store to search for 
     * supporting certificates and certificate trust lists (CTLs). This 
     * parameter can be {@code NULL} if no additional store is to be searched. 
     *@param pChainPara Pointer to a {@code CERT_CHAIN_PARA} structure that 
     * includes chain-building parameters.
     *@param dwFlags Flag values that indicates special processing. See MSDN.
     *@return handle to the chain context created. When you have finished using 
     * the chain context, release the chain by calling the 
     * CertFreeCertificateChain function. 
     */
    public native int CertGetCertificateChain (
            int hChainEngine,
            int pCertContext, 
            int pTime,
            int hAdditionalStore,
            int pChainPara,
            int dwFlags) throws CryptoAPIException;
    
    
    /**Frees a certificate chain by reducing its reference count. If the 
     * reference count becomes zero, memory allocated for the chain is released.
     *<p>Wrapped function:</p> 
     *<pre>
     *VOID WINAPI CertFreeCertificateChain(
     *PCCERT_CHAIN_CONTEXT pChainContext
     *);
     *</pre>
     *@param pChainContext Pointer to a {@code CERT_CHAIN_CONTEXT} certificate chain 
     * context to be freed. If the reference count on the context reaches zero, 
     * the storage allocated for the context is freed. 
     */
     public native void CertFreeCertificateChain(
             int pChainContext)throws CryptoAPIException;

    
    





}