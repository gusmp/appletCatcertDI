package org.catcert.gui;

import java.awt.Color;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStoreException;
import java.util.ResourceBundle;
import java.util.Vector;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.catcert.AppletSignatura;
import org.catcert.crypto.keyStoreImpl.CertificateStore;
import org.catcert.crypto.keyStoreImpl.CertificateStoreException;
import org.catcert.utils.Browsers;
import org.catcert.utils.OSName;

//import sun.misc.BASE64Decoder;

/**
 * 
 * @author oburgos
 * @author aciffone
 *
 */
public class CertSelectionDialog {

	private boolean Result = false;
	// s'utilitza per a tenir una unica variable per als
	// tres possibles paths (pkcs11, pkcs12, jks) 
	private String keyStoreLocation; 
	private int keystoreType;
	private CertificateStore keystore;
	private String alias;
	private char[] pin;
	private Vector<String> allowed_CAs;
	private Vector<String> allowed_OIDs;
	private String CN;
	private String subjectText;
	private Color color;
	private ImageIcon logo;
	private ResourceBundle txt;
	private boolean psisValidation;
	private boolean showContent;
	private String document_to_sign;
	private int doc_type;

	/**
	 * 
	 * @param keystoreType
	 * @param pkcs11file
	 * @param pkcs12file
	 * @param selected_alias
	 * @param CAs
	 * @param selected_CN
	 * @throws IOException 
	 */
	public CertSelectionDialog(int keystoreType, String keystoreFile, Vector<String> CAs, Vector<String> OIDs, 
			String selected_alias, String selected_CN, String subject_Text, Color appletColor, String appletLogo, 
			ResourceBundle txt, boolean psisValidation, boolean showContent, String document_to_sign, int doc_type) throws IOException {
		this.keystoreType = keystoreType;
		this.keyStoreLocation = keystoreFile;
		this.allowed_CAs = CAs;
		this.allowed_OIDs = OIDs;
		this.alias = selected_alias;
		this.CN = selected_CN;
		this.subjectText = subject_Text;
		this.color = appletColor;
		this.showContent = showContent;
		this.document_to_sign = document_to_sign;
		this.doc_type = doc_type;

		if (appletLogo != null)
			this.logo = new ImageIcon(javax.xml.bind.DatatypeConverter.parseBase64Binary(appletLogo));
		else {
			URL url = CertSelectionDialog.class.getResource("/org/catcert/gui/logo.png");
			this.logo = new ImageIcon(url);
		}
		this.txt = txt;
		this.psisValidation = psisValidation;
	}

	/**
	 * 
	 * @param possibilities
	 * @throws IOException 
	 */
	private void showCertificatesDialog(Object[] possibilities) {
		ComboBox availableCerts = new ComboBox(possibilities);
		availableCerts.setPrototypeDisplayValue("123456789012345678901234");

		ImageIcon customLogo = logo;		
		JLabel logoLabel = new JLabel(customLogo);
		

		JLabel avis = new JLabel(txt.getString("legalText"));
		
		Object[] options = {txt.getString("okButton"), txt.getString("cancelButton")};
		//		Checkbox psisValidation = new Checkbox("Validar contra PSIS", this.psisValidation);
		//		Object[] message = new Object[] {logoLabel, avis, "\n", txt.getString("select"), availableCerts, psisValidation};
		// GUS
		Object[] message = null;
		if (showContent == true)
		{
			if (doc_type == AppletSignatura.B64fileContent)
			{
				document_to_sign = new String(javax.xml.bind.DatatypeConverter.parseBase64Binary(document_to_sign));
			}
			JTextArea txt2 = new JTextArea(document_to_sign);
			txt2.setWrapStyleWord(true);
			txt2.setEditable(false);
			txt2.setColumns(60);
			//txt2.setLineWrap(true);
			JScrollPane msg = new JScrollPane(txt2);
			msg.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
			message = new Object[] {logoLabel, avis, msg, "\n", txt.getString("select"), availableCerts};
		}
		else
		{
			message = new Object[] {logoLabel, avis, "\n", txt.getString("select"), availableCerts};
		}
		// GUS
		
		if(new ColorJOptionPane(color).showCATCertDialog(null, message, "", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0])== JOptionPane.OK_OPTION) {			
			alias = keystore.getAliasFromCN((String)availableCerts.getSelectedItem());
			//			this.psisValidation = psisValidation.getState();
			Result = true;
		}
	}

	/**
	 * 
	 * @return
	 * @throws IOException 
	 */
	private boolean showPINinputDialog(){

		ImageIcon customLogo = logo;		
		JLabel logoLabel = new JLabel(customLogo);
		//JLabel logoLabel = new JLabel("123456789");
		
		JPasswordField pwd = new JPasswordField();		

		Object[] options = {txt.getString("okButton"), txt.getString("cancelButton")};
		Object[] message = {logoLabel, new JLabel(txt.getString("label")), txt.getString("pinText"), pwd };

		boolean endDialog = false;

		while(!endDialog) {
			if((new ColorJOptionPane(color).showCATCertDialog(null, message, "", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0])) == JOptionPane.OK_OPTION) {
				pin = pwd.getPassword();
				// Fem l'accés al keystore per detectar pwd erroni	aplica per a:
				// CertificateStore.Smartcard_keystore
				// CertificateStore.PKCS12_keystore
				// CertificateStore.Java_keystore
				try {
					keystore = new CertificateStore(keystoreType, keyStoreLocation, pin);
					endDialog = true;
				} catch (CertificateStoreException e) {
					options = new Object[]{txt.getString("okButton")};
					// msg d'error en funció del keyStoreType
					String errorMessage = txt.getString("errorAccesContent" + keystoreType);				
					new ColorJOptionPane(color).showCATCertDialog(null, errorMessage + e.getMessage(), txt.getString("Error"), JOptionPane.DEFAULT_OPTION, JOptionPane.ERROR_MESSAGE, null, options, options[0]);
					e.printStackTrace();
					pwd.setText("");
					options = new Object[] {txt.getString("okButton"), txt.getString("cancelButton")};
				}
			}
			else 
				return false;
		}
		return true;
	}		

	/**
	 * 
	 * @return
	 * @throws CertificateStoreException
	 * @throws IOException 
	 */
	public boolean run() throws CertificateStoreException {

		if(keystoreType == CertificateStore.Generic_keystore){		
			//detecció del sistema operatiu del client
			OSName currentOS = OSName.getOSName();
			System.out.println("Current OS: "+currentOS);

			//detecció del navegador del client
			Browsers browser = org.catcert.utils.BrowserUtils.detectBrowser();

			//actualitzem del valor del tipus de keystore
			if(currentOS.isWindows()){
				if(browser.equals(Browsers.EXPLORER) || browser.equals(Browsers.CHROME)){
					keystoreType = CertificateStore.MS_keystore;	
				}else if(browser.equals(Browsers.FIREFOX) || browser.equals(Browsers.MOZILLA)){
					keystoreType = CertificateStore.Mozilla_keystore;
				}else{
					// per la resta de navegadors
					keystoreType = CertificateStore.MS_keystore;
				}
			}else if (currentOS.isLinux()){
				if(browser.equals(Browsers.FIREFOX) || browser.equals(Browsers.MOZILLA)){
					keystoreType = CertificateStore.Mozilla_keystore;
				}
			}else if(currentOS.isMacOSX()){
				// check that browser is not null...
				if(browser.equals(Browsers.FIREFOX) || browser.equals(Browsers.MOZILLA)){
					keystoreType = CertificateStore.Mozilla_keystore;
				}else{
					keystoreType = CertificateStore.MacOSX_keystore;
				}
			}		
		}

		//Lògica segons el que mostrar...
		switch(keystoreType) {
		case CertificateStore.Smartcard_keystore:
		case CertificateStore.PKCS12_keystore:
		case CertificateStore.Java_keystore:
			if(!showPINinputDialog()){
				// si hi ha algun problema amb el pin retornem
				return false;
			}			
			break;
		case CertificateStore.MS_keystore:
		case CertificateStore.Mozilla_keystore:
			keystore = new CertificateStore(keystoreType, null, null);						
			break;
		case CertificateStore.MacOSX_keystore:
			// MAC no accepta un password null... aleshores li posem qualsevol cosa
			pin = "nonnull".toCharArray(); 
			keystore = new CertificateStore(keystoreType, null, null);						
			break;
		
		}
		
		// Filtratges per els paràmetres de l'applet

		// Si tenim l'alias...		
		if(alias != null && !alias.equals("")) {
			// Comprovem que l'alias existeixi
			try {
				if(!keystore.isSelectedAliasInKeystore(alias))
					throw new CertificateStoreException(txt.getString("missingAlias"));
				Result = true;
			} catch (KeyStoreException e) {
				e.printStackTrace();
				throw new CertificateStoreException(e.getMessage());
			}				
		}
		// Si tenim un CN únic...
		else if(CN != null && !CN.equals("")) {
			// Comprovem que el CN existeixi i sigui únic, sinó mostrar llista de coincidències
			Object[] sigingCertificates = keystore.getSigningCertificates(allowed_CAs, allowed_OIDs, CN);
			if(sigingCertificates.length == 1) {
				alias = keystore.getAliasFromCN((String)sigingCertificates[0]);
				Result = true;
			}
			else
				showCertificatesDialog(sigingCertificates);
		}
		else
			showCertificatesDialog(keystore.getSigningCertificates(allowed_CAs, allowed_OIDs, subjectText));
		
		return Result;
	}

	/**
	 * 
	 * @return
	 */
	public CertificateStore getStore() {
		return keystore;
	}

	/**
	 * 
	 * @return
	 */
	public String getSelectedAlias() {
		return alias;
	}

	/**
	 * 
	 * @return
	 */
	public char[] getPIN() {
		return pin;
	}

	/**
	 * 
	 * @return
	 */
	public boolean getPsisValidation() {
		return psisValidation;
	}
}