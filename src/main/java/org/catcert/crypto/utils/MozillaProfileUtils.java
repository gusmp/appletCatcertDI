package org.catcert.crypto.utils;

import java.io.File;
import java.io.FileFilter;

import org.catcert.utils.AppletConstants;
import org.catcert.utils.OSName;

public class MozillaProfileUtils {

    /**
     * Obtenció del directori del perfil de Firefox en funció del sistema operatiu del client.
     * @return path del directori del perfil per defecte de Firefox
     */
    public static String getFirefoxProfile(OSName currentOS) {    
    	/*
         * Windows Vista -> Users\<NombreUsuario>\AppData\Roaming\Mozilla\Firefox
         * Windows 2000, XP, Server 2003 -> Documents and Settings\<NombreUsuario>\Datos de Programa\Mozilla\Firefox 
         * Windows NT -> WINNT\Profiles\<NombreUsuario>\Application Data\Mozilla\Firefox 
         * Windows 98, ME -> Windows\Application Data\Mozilla\Firefox Mac OS X ~/Library/Application Support/Firefox
         * Sistemas Linux y Unix ~/.mozilla/firefox
         */

        String mozillaProfilesPath = "";

        if (currentOS.isLinux()) {
            mozillaProfilesPath = AppletConstants.USER_HOME + AppletConstants.LINUX_FIREFOX_PATH;
        }

        if (currentOS.isWin9x()) {
            mozillaProfilesPath = AppletConstants.WINDIR + AppletConstants.WIN9X_APPDATA_PATH + AppletConstants.WIN_FIREFOX_PATH;
        }

        if (currentOS.isWinNTorSuperior()) {
            mozillaProfilesPath = AppletConstants.APPDATA_FOLDER + AppletConstants.WIN_FIREFOX_PATH;
        }
        
        if (currentOS.isWindowsVista()) {
            mozillaProfilesPath = AppletConstants.USER_HOME + AppletConstants.WV_FIREFOX_PATH;
        }

        System.out.println("Carpeta de profiles: " + mozillaProfilesPath);

        return readProfileFromDir(mozillaProfilesPath);
    }
    
    
    /**
     * Obtenció del perfil per defecte.
     * @param dirPath directori on es troben els perfils de Firefox
     * @return perfil per defecte
     */
    private static String readProfileFromDir(String dirPath) {
        String profile = "";

        File dir = new File(dirPath);

        File[] profilesFiles;

        //només directoris
        FileFilter fileFilter = new FileFilter() {
            public boolean accept(File file) {
                return file.isDirectory();
            }
        };
        profilesFiles = dir.listFiles(fileFilter);

        if(profilesFiles!=null && profilesFiles.length>0){
	        for (File profileDir : profilesFiles) {
	        	//cal fer el resplace per a que funcioni amb Firefox
	            profile = profileDir.getAbsolutePath().replace(AppletConstants.ANTISLASH, AppletConstants.SLASH);
	            //fem servir el perfil 'default'
	            if (profile.endsWith(AppletConstants.MOZILLA_LINUX_PROFILE) || profile.contains(AppletConstants.S_DEFAULT)) {
	                System.out.println("Perfil seleccionat: " + profile);
	                return profile;
	            }
	        }
        }
        return "";
    }
	
}
