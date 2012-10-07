package org.catcert.utils;


public class AppletConstants {

    //slash
    public static final String   ANTISLASH                  = "\\";
    public static final String   SLASH                      = "/";
    public static final String   BLANK                      = " ";
	
    //properties
    public static final String   PROPERTY_OS                = "os.name";
    public static final String   PROPERTY_USER_DIR          = "user.dir";
    public static final String   USER_DIR                   = System.getProperty(PROPERTY_USER_DIR);

    public static final String   PROPERTY_USER_HOME         = "user.home";
    public static final String   USER_HOME                  = System.getProperty(PROPERTY_USER_HOME);

    public static final String   PROPERTY_JAVA_LIBRARY_PATH = "java.library.path";
    public static final String   JAVA_LIBRARY_PATH          = System.getProperty(PROPERTY_JAVA_LIBRARY_PATH).toLowerCase();

    public static final String   ENV_VAR_APPDATA            = "appdata";
    public static final String   ENV_VAR_WINDIR             = "windir";

    public static final String   PROPERTY_FILE_SEPARATOR    = "file.separator";
    public static final String   FILE_SEPARATOR             = System.getProperty(PROPERTY_FILE_SEPARATOR);

    public static final String   APPDATA_FOLDER             = System.getenv(ENV_VAR_APPDATA);
    public static final String   WINDIR                     = System.getenv(ENV_VAR_WINDIR);
    public static final String   SYSTEM32PATH               = "System32";
    public static final String   WINLIBSPATH                = WINDIR + FILE_SEPARATOR + SYSTEM32PATH + FILE_SEPARATOR;

    //default profile
    public static final String   S_DEFAULT                  = "default";
    public static final String   MOZILLA_LINUX_PROFILE      = "slt";

    //paths
    
    //Windows app data
    public static final String   WIN9X_APPDATA_PATH         = FILE_SEPARATOR + "Application Data" + FILE_SEPARATOR;

    //Firefox
    public static final String   LINUX_FIREFOX_PATH         = FILE_SEPARATOR + ".mozilla" + FILE_SEPARATOR + "firefox" + FILE_SEPARATOR;
    public static final String   WIN_FIREFOX_PATH           = FILE_SEPARATOR + "Mozilla" + FILE_SEPARATOR + "Firefox" + FILE_SEPARATOR + "Profiles" + FILE_SEPARATOR;
    public static final String   WV_FIREFOX_PATH            = FILE_SEPARATOR + "AppData" + FILE_SEPARATOR + "Roaming" + FILE_SEPARATOR + "Mozilla" + FILE_SEPARATOR + "Firefox" + FILE_SEPARATOR + "Profiles" + FILE_SEPARATOR;    

    //Mozilla
    public static final String   LINUX_MOZILLA_PATH         = FILE_SEPARATOR + ".mozilla" + FILE_SEPARATOR + "default" + FILE_SEPARATOR;
    public static final String   WIN_MOZILLA_PATH           = FILE_SEPARATOR + "Mozilla" + FILE_SEPARATOR + "Profiles" + FILE_SEPARATOR + "default"
                                                                    + FILE_SEPARATOR;

    //Netscape
    public static final String   LINUX_NETSCAPE_PATH        = FILE_SEPARATOR + ".netscape" + FILE_SEPARATOR + "navigator" + FILE_SEPARATOR;
    public static final String   WIN_NETSCAPE_PATH          = FILE_SEPARATOR + "Netscape" + FILE_SEPARATOR + "Navigator" + FILE_SEPARATOR + "Profiles" + FILE_SEPARATOR;

    //detecció SO
    public static final String   S_NETSCAPE                 = "netscape";
    public static final String   S_NETSCAPE2                = "navigator";
    public static final String   S_MOZILLA                  = "mozilla.org" + FILE_SEPARATOR + "GRE";
    public static final String   S_MOZILLA2                 = "mozilla.org";
    public static final String	 S_EXPLORER					= "explorer";
    public static final String	 S_FIREFOX					= "firefox";
    public static final String   S_CHROME					= "google" + FILE_SEPARATOR + "chrome";

    //noms dels SO segons Sun
    public static final String   LINUX                      = "Linux";
    public static final String   WINDOWS95                  = "Windows 95";
    public static final String   WINDOWS98                  = "Windows 98";
    public static final String   WINDOWSXP                  = "Windows XP";
    public static final String   WINDOWSME                  = "Windows Me";
    public static final String   WINDOWS2K                  = "Windows 2000";
    public static final String   WINDOWSVISTA				= "Windows Vista";
    public static final String   MACOSX                     = "Mac OS X";
    public static final String   WINDOWSNT                  = "Windows NT";
    

    //resultats de validació de PSIS
	public static final String PSIS_RESULTMAJOR_OK = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";
	public static final String PSIS_RESULTMINOR_VALID = "urn:oasis:names:tc:dss:1.0:profiles:XSS:resultminor:valid:certificate:Definitive";
	public static final String PSIS_RESULTMINOR_EXPIRED = "urn:oasis:names:tc:dss:1.0:profiles:XSS:resultminor:invalid:certificate:Expired";
	public static final String PSIS_RESULTMINOR_REVOKED = "urn:oasis:names:tc:dss:1.0:profiles:XSS:resultminor:invalid:certificate:Revoked";
	public static final String PSIS_RESULTMINOR_UNKNOWN = "urn:oasis:names:tc:dss:1.0:profiles:XSS:resultminor:unknown:certificate:Status_NoCertificatePathFound";
	public static final String PSIS_RESULTMINOR_POLICYNOTSUPPORTED = "urn:oasis:names:tc:dss:1.0:profiles:XSS:resultminor:invalid:certificate:CertificatePolicyNotSupported";
	

}
