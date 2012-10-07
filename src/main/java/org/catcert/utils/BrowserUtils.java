package org.catcert.utils;

/**
 * Classe d'utilitats per detecció de navegador.
 *
 */
public class BrowserUtils {

    /**
     * Detecta el navegador del client que està executant l'applet, en funció del classpath de Java.
     * @return navegador detectat
     */
    public static Browsers detectBrowser() {
        
    	Browsers detBrowser = Browsers.NOTFOUND;
        
    	/*
         * Busca en el path si estan las cadenas mozilla o netscape o navigator,
         * no deberian usarse estos navegadores y si estan en otros directorios
         * cogera el repositorio de firefox
         */
        if (AppletConstants.JAVA_LIBRARY_PATH.contains(AppletConstants.S_EXPLORER)) {
            detBrowser = Browsers.EXPLORER;
        }

        if (AppletConstants.JAVA_LIBRARY_PATH.contains(AppletConstants.S_FIREFOX)) {
            detBrowser = Browsers.FIREFOX;
        }

        if (AppletConstants.JAVA_LIBRARY_PATH.contains(AppletConstants.S_CHROME)) {
            detBrowser = Browsers.CHROME;
        }
        
        if (AppletConstants.JAVA_LIBRARY_PATH.contains(AppletConstants.S_MOZILLA) || AppletConstants.JAVA_LIBRARY_PATH.contains(AppletConstants.S_MOZILLA2)) {
            // Navegador inutil
            detBrowser = Browsers.MOZILLA;
        }

        if (AppletConstants.JAVA_LIBRARY_PATH.contains(AppletConstants.S_NETSCAPE) || AppletConstants.JAVA_LIBRARY_PATH.contains(AppletConstants.S_NETSCAPE2)) {
            // Navegador deprecated
            detBrowser = Browsers.NETSCAPE;
        }
        
        System.out.println("Class path: "+AppletConstants.JAVA_LIBRARY_PATH);
        System.out.println("Detected browser: "+detBrowser);
        
        return detBrowser;
        
    }
	
}
