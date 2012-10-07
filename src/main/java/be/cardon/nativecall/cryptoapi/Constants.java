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

/**Wrapper for the CryptoAPI constants as defined in {@code WinCrypt.h} (<b>this 
 * class is not complete !</b>)
 *
 * @author Rodolphe
 */
public class Constants {
    
    /** Creates a new instance of Constants */
    public Constants() {
    }
    
    //static final int X509_ASN_ENCODING;
    
    //Doc about constants : see MSDN library => MSDN Library => Cryptography and wincript.h (16000 lines !)
    public final static int CERT_STORE_PROV_MSG = 1;
    public final static int CERT_STORE_PROV_MEMORY  = 2;
    public final static int CERT_STORE_PROV_FILE = 3;
    public final static int CERT_STORE_PROV_REG  = 4;
    public final static int CERT_STORE_PROV_PKCS7 = 5;
    public final static int CERT_STORE_PROV_SERIALIZED = 6;
    public final static int CERT_STORE_PROV_FILENAME_A = 7; // ASCII
    public final static int CERT_STORE_PROV_FILENAME_W = 8; // Unicode
    public final static int CERT_STORE_PROV_FILENAME = CERT_STORE_PROV_FILENAME_W;
    public final static int CERT_STORE_PROV_SYSTEM_A  = 9;  // pvPara is ASCII (1 byte/char)
    public final static int CERT_STORE_PROV_SYSTEM_W  = 10; // pvPara is Unicode (2 bytes/char)
    public final static int CERT_STORE_PROV_SYSTEM  = CERT_STORE_PROV_SYSTEM_W;
    public final static int CERT_STORE_PROV_COLLECTION  = 11;
    public final static int CERT_STORE_PROV_SYSTEM_REGISTRY_A = 12;
    public final static int CERT_STORE_PROV_SYSTEM_REGISTRY_W = 13;
    public final static int CERT_STORE_PROV_SYSTEM_REGISTRY = CERT_STORE_PROV_SYSTEM_REGISTRY_W;
    public final static int CERT_STORE_PROV_PHYSICAL_W = 14;
    public final static int CERT_STORE_PROV_PHYSICAL = CERT_STORE_PROV_PHYSICAL_W;
    public final static int CERT_STORE_PROV_SMART_CARD_W  = 15;
    public final static int CERT_STORE_PROV_SMART_CARD = CERT_STORE_PROV_SMART_CARD_W;
    public final static int CERT_STORE_PROV_LDAP_W  = 16;
    public final static int CERT_STORE_PROV_LDAP = CERT_STORE_PROV_LDAP_W;
    
    // Location of the system store:
    public final static int CERT_SYSTEM_STORE_LOCATION_MASK = 0x00FF0000;
    public final static int CERT_SYSTEM_STORE_LOCATION_SHIFT = 16;

    //  Registry: HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE
    public final static int CERT_SYSTEM_STORE_CURRENT_USER_ID = 1;
    public final static int CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2;
    //  Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Services
    public final static int CERT_SYSTEM_STORE_CURRENT_SERVICE_ID = 4;
    public final static int CERT_SYSTEM_STORE_SERVICES_ID = 5;
    //  Registry: HKEY_USERS
    public final static int CERT_SYSTEM_STORE_USERS_ID = 6;
    //  Registry: HKEY_CURRENT_USER\Software\Policies\Microsoft\SystemCertificates
    public final static int CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID = 7;
    //  Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates
    public final static int CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID = 8;
    //  Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseCertificates
    public final static int CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID = 9;
    
    //dwFlags for CERT_STORE_PROV_SYSTEM, CERT_STORE_PROV_SYSTEM_REGISTER, and CERT_STORE_PROV_PHYSICAL  to
    // specify system store registry locations:
    public final static int CERT_SYSTEM_STORE_CURRENT_USER  =
      (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    public final static int CERT_SYSTEM_STORE_LOCAL_MACHINE =
      (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    public final static int CERT_SYSTEM_STORE_CURRENT_SERVICE =
    (CERT_SYSTEM_STORE_CURRENT_SERVICE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    public final static int CERT_SYSTEM_STORE_SERVICES =
    (CERT_SYSTEM_STORE_SERVICES_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    public final static int CERT_SYSTEM_STORE_USERS =
    (CERT_SYSTEM_STORE_USERS_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    public final static int CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY =
    (CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    public final static int CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY  =
    (CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    public final static int CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE =
    (CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    
      //  Certificate and Message encoding types (wincrypt.h line 2060)
    public final static int CERT_ENCODING_TYPE_MASK   =  0x0000FFFF;
    public final static int CMSG_ENCODING_TYPE_MASK   =  0xFFFF0000;
    public final static int GET_CERT_ENCODING_TYPE(int X){
        return X & CERT_ENCODING_TYPE_MASK;
    }
    public final static int GET_CMSG_ENCODING_TYPE(int X){
        return X & CMSG_ENCODING_TYPE_MASK;
    }
    public final static int CRYPT_ASN_ENCODING =         0x00000001;
    public final static int CRYPT_NDR_ENCODING =         0x00000002;
    public final static int X509_ASN_ENCODING =          0x00000001;
    public final static int X509_NDR_ENCODING =          0x00000002;
    public final static int PKCS_7_ASN_ENCODING =        0x00010000;
    public final static int PKCS_7_NDR_ENCODING =        0x00020000;
    
    
    //+-------------------------------------------------------------------------
//  Certificate name types ligne 12761
//--------------------------------------------------------------------------
    public final static int CERT_NAME_EMAIL_TYPE = 1;
    public final static int CERT_NAME_RDN_TYPE = 2;
    public final static int CERT_NAME_ATTR_TYPE =3;
    public final static int CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
    public final static int CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5;
    public final static int CERT_NAME_DNS_TYPE = 6;
    public final static int CERT_NAME_URL_TYPE = 7;
    public final static int CERT_NAME_UPN_TYPE = 8;

    //for CryptAcquireCertificatePrivateKey, line 12158
    public final static int CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001;
    public final static int CRYPT_ACQUIRE_USE_PROV_INFO_FLAG =0x00000002;
    public final static int CRYPT_ACQUIRE_COMPARE_KEY_FLAG= 0x00000004;
    public final static int CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;
    
    public final static int AT_KEYEXCHANGE = 1;
    public final static int AT_SIGNATURE = 2;



    // Algorithm classes
    public final static int ALG_CLASS_ANY             =      (0);
    public final static int ALG_CLASS_SIGNATURE       =      (1 << 13);
    public final static int ALG_CLASS_MSG_ENCRYPT     =      (2 << 13);
    public final static int ALG_CLASS_DATA_ENCRYPT    =      (3 << 13);
    public final static int ALG_CLASS_HASH            =      (4 << 13);
    public final static int ALG_CLASS_KEY_EXCHANGE    =      (5 << 13);
    public final static int ALG_CLASS_ALL             =      (7 << 13);

// Algorithm types
    public final static int ALG_TYPE_ANY              =      (0);
    public final static int ALG_TYPE_DSS              =      (1 << 9);
    public final static int ALG_TYPE_RSA              =      (2 << 9);
    public final static int ALG_TYPE_BLOCK            =      (3 << 9);
    public final static int ALG_TYPE_STREAM           =      (4 << 9);
    public final static int ALG_TYPE_DH               =      (5 << 9);
    public final static int ALG_TYPE_SECURECHANNEL    =      (6 << 9);

// Generic sub-ids
    public final static int  ALG_SID_ANY        =             (0);

// Some RSA sub-ids
    public final static int ALG_SID_RSA_ANY           =      0;
    public final static int ALG_SID_RSA_PKCS          =      1;
    public final static int ALG_SID_RSA_MSATWORK      =      2;
    public final static int ALG_SID_RSA_ENTRUST       =      3;
    public final static int ALG_SID_RSA_PGP           =      4;

// Some DSS sub-ids
//
    public final static int ALG_SID_DSS_ANY            =     0;
    public final static int ALG_SID_DSS_PKCS           =     1;
    public final static int ALG_SID_DSS_DMS            =     2;

// Block cipher sub ids
// DES sub_ids
    public final static int ALG_SID_DES              =       1;
    public final static int ALG_SID_3DES             =       3;
    public final static int ALG_SID_DESX             =       4;
    public final static int ALG_SID_IDEA             =       5;
    public final static int ALG_SID_CAST             =       6;
    public final static int ALG_SID_SAFERSK64        =       7;
    public final static int ALG_SID_SAFERSK128       =       8;
    public final static int ALG_SID_3DES_112         =       9;
    public final static int ALG_SID_CYLINK_MEK       =       12;
    public final static int ALG_SID_RC5              =       13;
    public final static int ALG_SID_AES_128          =       14;
    public final static int ALG_SID_AES_192          =       15;
    public final static int ALG_SID_AES_256          =       16;
    public final static int ALG_SID_AES              =       17;

// Fortezza sub-ids
    public final static int ALG_SID_SKIPJACK         =       10;
    public final static int ALG_SID_TEK              =       11;

// KP_MODE
    public final static int CRYPT_MODE_CBCI          =       6;       // ANSI CBC Interleaved
    public final static int CRYPT_MODE_CFBP          =       7;       // ANSI CFB Pipelined
    public final static int CRYPT_MODE_OFBP          =       8;       // ANSI OFB Pipelined
    public final static int CRYPT_MODE_CBCOFM        =       9;       // ANSI CBC + OF Masking
    public final static int CRYPT_MODE_CBCOFMI       =       10;      // ANSI CBC + OFM Interleaved

// RC2 sub-ids
    public final static int ALG_SID_RC2                  =   2;

// Stream cipher sub-ids
    public final static int ALG_SID_RC4                  =   1;
    public final static int ALG_SID_SEAL                 =   2;

// Diffie-Hellman sub-ids
    public final static int ALG_SID_DH_SANDF             =   1;
    public final static int ALG_SID_DH_EPHEM             =   2;
    public final static int ALG_SID_AGREED_KEY_ANY       =   3;
    public final static int ALG_SID_KEA                  =   4;

// Hash sub ids
    public final static int ALG_SID_MD2                 =    1;
    public final static int ALG_SID_MD4                 =    2;
    public final static int ALG_SID_MD5                 =    3;
    public final static int ALG_SID_SHA                 =    4;
    public final static int ALG_SID_SHA1                =    4;
    public final static int ALG_SID_MAC                 =    5;
    public final static int ALG_SID_RIPEMD              =    6;
    public final static int ALG_SID_RIPEMD160           =    7;
    public final static int ALG_SID_SSL3SHAMD5          =    8;
    public final static int ALG_SID_HMAC                =    9;
    public final static int ALG_SID_TLS1PRF             =    10;
    public final static int ALG_SID_HASH_REPLACE_OWF    =    11;
    public final static int ALG_SID_SHA_256             =    12;
    public final static int ALG_SID_SHA_384             =    13;
    public final static int ALG_SID_SHA_512             =    14;


// secure channel sub ids
    public final static int ALG_SID_SSL3_MASTER            = 1;
    public final static int ALG_SID_SCHANNEL_MASTER_HASH   = 2;
    public final static int ALG_SID_SCHANNEL_MAC_KEY       = 3;
    public final static int ALG_SID_PCT1_MASTER            = 4;
    public final static int ALG_SID_SSL2_MASTER            = 5;
    public final static int ALG_SID_TLS1_MASTER            = 6;
    public final static int ALG_SID_SCHANNEL_ENC_KEY       = 7;

// Our silly example sub-id
    public final static int ALG_SID_EXAMPLE            =     80;

// algorithm identifier definitions
    public final static int CALG_MD2            =    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2);
    public final static int CALG_MD4            =    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4);
    public final static int CALG_MD5            =    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5);
    public final static int CALG_SHA            =    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA);
    public final static int CALG_SHA1           =    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1);
    public final static int CALG_MAC            =    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MAC);
    public final static int CALG_RSA_SIGN       =    (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY);
    public final static int CALG_DSS_SIGN       =    (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY);
    public final static int CALG_NO_SIGN        =    (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_ANY);
    public final static int CALG_RSA_KEYX       =    (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_ANY);
    public final static int CALG_DES            =    (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_DES);

    public final static int CALG_3DES_112         =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES_112);
    public final static int CALG_3DES             =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES);
    public final static int CALG_DESX             =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_DESX);
    public final static int CALG_RC2              =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_RC2);
    public final static int CALG_RC4              =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_RC4);
    public final static int CALG_SEAL             =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_SEAL);
    public final static int CALG_DH_SF            =  (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH_SANDF);
    public final static int CALG_DH_EPHEM         =  (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH_EPHEM);
    public final static int CALG_AGREEDKEY_ANY    =  (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_AGREED_KEY_ANY);
    public final static int CALG_KEA_KEYX         =  (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_KEA);
    public final static int CALG_HUGHES_MD5       =  (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_MD5);
    public final static int CALG_SKIPJACK         =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SKIPJACK);
    public final static int CALG_TEK              =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TEK);
    public final static int CALG_CYLINK_MEK       =  (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_CYLINK_MEK);
    public final static int CALG_SSL3_SHAMD5      =  (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5);
    public final static int CALG_SSL3_MASTER      =  (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SSL3_MASTER);
    public final static int CALG_SCHANNEL_MASTER_HASH =  (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_MASTER_HASH);
    public final static int CALG_SCHANNEL_MAC_KEY  = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_MAC_KEY);
    public final static int CALG_SCHANNEL_ENC_KEY  = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_ENC_KEY);
    public final static int CALG_PCT1_MASTER       = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_PCT1_MASTER);
    public final static int CALG_SSL2_MASTER       = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SSL2_MASTER);
    public final static int CALG_TLS1_MASTER       = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_TLS1_MASTER);
    public final static int CALG_RC5               = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_RC5);
    public final static int CALG_HMAC              = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC);
    public final static int CALG_TLS1PRF           = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF);
    public final static int CALG_HASH_REPLACE_OWF  = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF);
    public final static int CALG_AES_128           = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_128);
    public final static int CALG_AES_192           = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_192);
    public final static int CALG_AES_256           = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_256);
    public final static int CALG_AES               = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES);
    public final static int CALG_SHA_256           = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256);
    public final static int CALG_SHA_384           = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384);
    public final static int CALG_SHA_512           = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512);

//line 12480
//+-------------------------------------------------------------------------
//  Certificate name string types
//--------------------------------------------------------------------------
    public final static int CERT_SIMPLE_NAME_STR       = 1;
    public final static int CERT_OID_NAME_STR          = 2;
    public final static int CERT_X500_NAME_STR         = 3;
    
//+-------------------------------------------------------------------------
//  Certificate name string type flags OR'ed with the above types
//--------------------------------------------------------------------------    
    public final static int CERT_NAME_STR_SEMICOLON_FLAG   = 0x40000000;
    public final static int CERT_NAME_STR_NO_PLUS_FLAG     = 0x20000000;
    public final static int CERT_NAME_STR_NO_QUOTING_FLAG  = 0x10000000;
    public final static int CERT_NAME_STR_CRLF_FLAG        = 0x08000000;
    public final static int CERT_NAME_STR_COMMA_FLAG       = 0x04000000;
    public final static int CERT_NAME_STR_REVERSE_FLAG     = 0x02000000;

    public final static int CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG    = 0x00010000;
    public final static int CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG  = 0x00020000;
    public final static int CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG = 0x00040000;
    public final static int CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG  = 0x00080000;

// lines 7098 
//+-------------------------------------------------------------------------
//  Certificate, CRL and CTL property IDs
//
//  See CertSetCertificateContextProperty or CertGetCertificateContextProperty
//  for usage information.
//--------------------------------------------------------------------------
public final static int CERT_KEY_PROV_HANDLE_PROP_ID      =  1;
public final static int CERT_KEY_PROV_INFO_PROP_ID        =  2;
public final static int CERT_SHA1_HASH_PROP_ID            =  3;
public final static int CERT_MD5_HASH_PROP_ID             =  4;
public final static int CERT_HASH_PROP_ID                 =  CERT_SHA1_HASH_PROP_ID;
public final static int CERT_KEY_CONTEXT_PROP_ID          =  5;
public final static int CERT_KEY_SPEC_PROP_ID             =  6;
public final static int CERT_IE30_RESERVED_PROP_ID        =  7;
public final static int CERT_PUBKEY_HASH_RESERVED_PROP_ID =  8;
public final static int CERT_ENHKEY_USAGE_PROP_ID         =  9;
public final static int CERT_CTL_USAGE_PROP_ID            =  CERT_ENHKEY_USAGE_PROP_ID;
public final static int CERT_NEXT_UPDATE_LOCATION_PROP_ID =  10;
public final static int CERT_FRIENDLY_NAME_PROP_ID        =  11;
public final static int CERT_PVK_FILE_PROP_ID             =  12;
public final static int CERT_DESCRIPTION_PROP_ID          =  13;
public final static int CERT_ACCESS_STATE_PROP_ID         =  14;
public final static int CERT_SIGNATURE_HASH_PROP_ID       =  15;
public final static int CERT_SMART_CARD_DATA_PROP_ID      =  16;
public final static int CERT_EFS_PROP_ID                  =  17;
public final static int CERT_FORTEZZA_DATA_PROP_ID        =  18;
public final static int CERT_ARCHIVED_PROP_ID             =  19;
public final static int CERT_KEY_IDENTIFIER_PROP_ID       =  20;
public final static int CERT_AUTO_ENROLL_PROP_ID          =  21;
public final static int CERT_PUBKEY_ALG_PARA_PROP_ID      =  22;
public final static int CERT_CROSS_CERT_DIST_POINTS_PROP_ID= 23;
public final static int CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID   =  24;
public final static int CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID  =  25;
public final static int CERT_ENROLLMENT_PROP_ID           =  26;
public final static int CERT_DATE_STAMP_PROP_ID           =  27;
public final static int CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID = 28;
public final static int CERT_SUBJECT_NAME_MD5_HASH_PROP_ID = 29;
public final static int CERT_EXTENDED_ERROR_INFO_PROP_ID   = 30;
    
//certificate chain
public final static int USAGE_MATCH_TYPE_AND        = 0x00000000;
public final static int USAGE_MATCH_TYPE_OR         = 0x00000001;


//
// CryptGetProvParam
//
public final static int PP_ENUMALGS            = 1;
public final static int PP_ENUMCONTAINERS      = 2;
public final static int PP_IMPTYPE             = 3;
public final static int PP_NAME                = 4;
public final static int PP_VERSION             = 5;
public final static int PP_CONTAINER           = 6;
public final static int PP_CHANGE_PASSWORD     = 7;
public final static int PP_KEYSET_SEC_DESCR    = 8; // get/set security descriptor of keyset
public final static int PP_CERTCHAIN           = 9; // for retrieving certificates from tokens
public final static int PP_KEY_TYPE_SUBTYPE    = 10;
public final static int PP_PROVTYPE            = 16;
public final static int PP_KEYSTORAGE          = 17;
public final static int PP_APPLI_CERT          = 18;
public final static int PP_SYM_KEYSIZE         = 19;
public final static int PP_SESSION_KEYSIZE     = 20;
public final static int PP_UI_PROMPT           = 21;
public final static int PP_ENUMALGS_EX         = 22;
public final static int PP_ENUMMANDROOTS       = 25;
public final static int PP_ENUMELECTROOTS      = 26;
public final static int PP_KEYSET_TYPE         = 27;
public final static int PP_ADMIN_PIN           = 31;
public final static int PP_KEYEXCHANGE_PIN     = 32;
public final static int PP_SIGNATURE_PIN       = 33;
public final static int PP_SIG_KEYSIZE_INC     = 34;
public final static int PP_KEYX_KEYSIZE_INC    = 35;
public final static int PP_UNIQUE_CONTAINER    = 36;
public final static int PP_SGC_INFO            = 37;
public final static int PP_USE_HARDWARE_RNG    = 38;
public final static int PP_KEYSPEC             = 39;
public final static int PP_ENUMEX_SIGNING_PROT = 40;
public final static int PP_CRYPT_COUNT_KEY_USE = 41;

public final static int CRYPT_FIRST            = 1;
public final static int CRYPT_NEXT             = 2;
public final static int CRYPT_SGC_ENUM         = 4;

public final static int CRYPT_IMPL_HARDWARE    = 1;
public final static int CRYPT_IMPL_SOFTWARE    = 2;
public final static int CRYPT_IMPL_MIXED       = 3;
public final static int CRYPT_IMPL_UNKNOWN     = 4;
public final static int CRYPT_IMPL_REMOVABLE   = 8;

public final static int HP_ALGID               = 0x0001;  // Hash algorithm
public final static int HP_HASHVAL             = 0x0002;  // Hash value
public final static int HP_HASHSIZE            = 0x0004;  // Hash value size
public final static int HP_HMAC_INFO           = 0x0005;  // information for creating an HMAC



}


