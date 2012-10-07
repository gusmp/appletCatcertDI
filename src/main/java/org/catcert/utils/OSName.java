package org.catcert.utils;


/**
 * Classe d'utilitats per sistemes operatius.
 */
public enum OSName {
    WINDOWSXP(AppletConstants.WINDOWSXP), 
    WINDOWS95(AppletConstants.WINDOWS95), 
    WINDOWS98(AppletConstants.WINDOWS98), 
    WINDOWSME(AppletConstants.WINDOWSME), 
    LINUX(AppletConstants.LINUX), 
    WINDOWSNT(AppletConstants.WINDOWSNT), 
    WINDOWS2K(AppletConstants.WINDOWS2K), 
    WINDOWSVISTA(AppletConstants.WINDOWSVISTA),
    MACOSX(AppletConstants.MACOSX);

    private String javaOSName;

    OSName(String name) {
        this.javaOSName = name;
    }

    public String getJavaOSName() {
        return this.javaOSName;
    }

    public static OSName getOSName() {
        String osName = System.getProperty(AppletConstants.PROPERTY_OS);
        /*
         * Linux Windows 2000 Windows 95 Windows 98 Windows NT Windows XP MacOSX
         */
        for (OSName osNameTemp : OSName.values()) {
        	//System.out.println("osNameTemp.getJavaOSName(): "+osNameTemp.getJavaOSName());
            if (osNameTemp.getJavaOSName().equals(osName)) {
                return osNameTemp;
            }
        }
        
        return null;
        
    }

    public boolean isWin9x() {
        switch (this) {
        case WINDOWS95:
        case WINDOWS98:
        case WINDOWSME:
            return true;
        default:
            return false;
        }
    }

    public boolean isWinNTorSuperior() {
        switch (this) {
        case WINDOWS2K:
        case WINDOWSNT:
        case WINDOWSXP:
            return true;
        default:
            return false;
        }
    }
    
    public boolean isWindowsVista() {
        switch (this) {
        case WINDOWSVISTA:
            return true;
        default:
            return false;
        }
    }

    public boolean isWindows() {
        switch (this) {
        case WINDOWS2K:
        case WINDOWS95:
        case WINDOWS98:
        case WINDOWSME:
        case WINDOWSNT:
        case WINDOWSXP:
        case WINDOWSVISTA:
            return true;
        default:
            return false;
        }
    }

    public boolean isLinux() {
        if(OSName.LINUX.equals(this)) {
            return true;
        }
        return false;
    }
    
    public boolean isMacOSX(){
    	if(OSName.MACOSX.equals(this)){
    		return true;
    	}
    	return false;
    }

    public String toString() {
        return this.javaOSName.toString();
    }

}
