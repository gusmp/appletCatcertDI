package org.catcert;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.JApplet;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import netscape.javascript.JSObject;

import org.catcert.crypto.keyStoreImpl.CertificateStore;
import org.catcert.crypto.keyStoreImpl.CertificateStoreException;
import org.catcert.crypto.signImpl.CMSSignatureGeneration;
import org.catcert.crypto.signImpl.CMSSignatureGenerationException;
import org.catcert.crypto.signImpl.PDFSignatureGeneration;
import org.catcert.crypto.signImpl.PDFSignatureGenerationException;
import org.catcert.crypto.signImpl.TsaUrl;
import org.catcert.crypto.signImpl.XMLdsigGeneration;
import org.catcert.crypto.signImpl.XMLdsigGenerationException;
import org.catcert.crypto.utils.Utils;
import org.catcert.gui.CertSelectionDialog;
import org.catcert.gui.ColorJOptionPane;
import org.catcert.gui.DownloadProgressBar;
import org.catcert.gui.PdfInputsDialog;
import org.catcert.net.HTTPSender;
import org.catcert.net.HTTPSenderException;
import org.catcert.psis.PSISValidationException;
import org.catcert.utils.AppletUtils;
import org.catcert.utils.OSName;
import org.catcert.xfiledialog.XFileDialog;

//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;

/**
 * 
 * @author oburgos
 * @author Ciffone
 *
 */
@SuppressWarnings("unused")
public class AppletSignatura extends JApplet {

	private static final long serialVersionUID = 5866257002013051251L;
	private static final String CATCert = System.getProperty("user.home") + System.getProperty("file.separator") + "CATCert";
	private static ResourceBundle txt;

	//Languages
	private static final String CATALAN = "ca";
	private static final String SPANISH = "es";

	//Signature types static values
	private static final int CMS_attached = 1;
	private static final int CMS_detached = 2;
	private static final int CMS_detached_hash = 3;
	private static final int CMS_in_PDF = 4;
	private static final int XMLdsig_enveloped = 5;
	private static final int XMLdsig_enveloping = 6;
	private static final int XMLdsig_detached = 7;
	private static final int XMLdsig_detached_hash = 8;
	private static final int XAdES_BES_enveloped = 9;
	private static final int XAdES_BES_enveloping = 10;
	private static final int XAdES_BES_detached = 11;
	private static final int XAdES_BES_detached_hash = 12;
	private static final int XAdES_T_enveloped = 13;
	private static final int XAdES_T_enveloping = 14;
	private static final int XAdES_T_detached = 15;
	private static final int XAdES_T_detached_hash = 16;
	private static final int XAdES_C_enveloped = 17; //No implementat
	private static final int XAdES_C_enveloping = 18; //No implementat
	private static final int XAdES_C_detached = 19; //No implementat
	private static final int XAdES_C_detached_hash = 20; //No implementat
	private static final int CAdES_BES_attached = 21;
	private static final int CAdES_BES_detached = 22;
	private static final int CAdES_BES_detached_hash = 23;
	private static final int CAdES_BES_in_PDF = 24;
	private static final int CAdES_T_attached = 25;
	private static final int CAdES_T_detached = 26;
	private static final int CAdES_T_detached_hash = 27;
	private static final int CAdES_T_in_PDF = 28;
	private static final int CAdES_C_attached = 29; //No implementat
	private static final int CAdES_C_detached = 30; //No implementat
	private static final int CAdES_C_detached_hash = 31; //No implementat
	private static final int CAdES_C_in_PDF = 32; //No implementat

	// Available Hash algorithms
	private static final int SHA1 = 1;
	private static final int SHA224 = 2;
	private static final int SHA256 = 3;
	private static final int SHA384 = 4;
	private static final int SHA512 = 5;

	// Hash algorithm Id's
	private static final String SHA1ID = "SHA-1";
	private static final String SHA256ID = "SHA-256";
	private static final String SHA512ID = "SHA-512";

	//Output modes
	private static final int binary = 1;
	private static final int base64 = 2;
	private static final int xml = 3;
	private static final int pdf = 4;

	//Input document modes
	public static final int allFilesInDir = 1;
	public static final int singleFile = 2;
	public static final int hashDoc = 3;
	public static final int B64fileContent = 4;
	public static final int fileList = 5;
	public static final int urlFile = 6;
	public static final int form = 7;

	//Visible/invisible pdf signature
	private static final boolean invisiblePDFsignature = false;
	private static final boolean visiblePDFsignature = true;

	//Certification levels in PDF signature
	public static final int PDF_NOT_CERTIFIED = 0;
	public static final int PDF_CERTIFIED_NO_CHANGES_ALLOWED = 1;
	public static final int PDF_CERTIFIED_FORM_FILLING = 2;
	public static final int PDF_CERTIFIED_FORM_FILLING_AND_ANNOTATIONS = 3;

	//Save a local file copy
	private static final boolean doNotSaveLocalCopy = false;
	private static final boolean saveLocalCopy = true;

	//Show local file path in pop-up window
	private static final boolean showLocalCopyMessage = true;

	//Output signature document to form
	private static final boolean doNotupdateForm = false;
	private static final boolean updateForm = true;

	//Mandatory Parameters
	//-----------------
	private int keystore_type;
	//0=Generic keystore
	//1=MS Windows keystore, 2=PKCS12 keystore, 3=Smartcard keystore, 4=Mozilla keystore, 5=Java keystore, 6=MacOSX keystore
	private int signature_mode;
	//1=CMS attached, 2=CMS detached, 3=CMS detached(hash), 4=CMSinPDF, 
	//5=XMLdsig enveloped, 6=XMLdsig enveloping, 7=XMLdsig detached, 8=XMLdsig detached(hash),
	//9=XAdES-BES enveloped, 10=XAdES-BES enveloping, 11=XAdES-BES detached, 12=XAdES-BES detached(hash),
	//13=XAdES-T enveloped, 14=XAdES-T enveloping, 15=XAdES-T detached, 16=XAdES-T detached(hash),
	//17=XAdES-C enveloped, 18=XAdES-C enveloping, 19=XAdES-C detached, 20=XAdES-C detached(hash)
	//21=CAdES attached, 22=CAdES detached, 23=CAdES detached(hash), 24=CAdESinPDF,
	//25=CAdES-T attached, 26=CAdES-T detached, 27=CAdES-T detached(hash), 28=CAdES-TinPDF,
	//29=CAdES-C attached, 30=CAdES-C detached, 31=CAdES-C detached(hash), 32=CAdES-CinPDF,

	//Optional Parameters
	//-----------------

	//Hash algorithm to use
	private int hash_algorithm;

	//(directory/fileToSign path/hash value/B64File/url to file).
	private String document_to_sign;

	//(false, true) Returns generated signature using a Javscript event. False by default.
	private boolean js_event;	

	//(false, true) OnMultiSignature event return signatures or only js event. False by default
	private boolean js_multisignature_only_event;

	//(false, true) Saves local copy of signed document, false by default.
	private boolean local_file;

	//(false, true) Show a pop-up window showing the path of the saved signed document, true by default.
	private boolean local_file_result_message;

	//(1=directory, 2=single file, 3=hash, 4=B64 file content, 5=file list separated by ";") Single file by default.
	private int doc_type;	

	//(binary/base64/pdf/xml) CMS:default base64, XMLdsig:always XML, PDF:always PDF.
	private int output_mode;

	//(false, true) Update html form with signature value, false by default.	
	private boolean form_fill;

	//(name of html form) By default appletCATCertForm.
	private String form_fill_form;

	//(name of html control to fill inside form) Mandatory if form_fill is set to true.
	private String form_fill_field;

	//(output file absolute path) Only available for single file mode. If not specified, default name *_signat.extension.
	private Vector<String> output_filename;

	//(absolute file path) File containing PKCS#11 library. Mandatory if using Smartcard Keystore.
	private String pkcs11_file;

	//(absolute file path) File containing PFX/PKCS#12. Mandatory if using PKCS12 Keystore.
	private String pkcs12_file;

	//(absolute file path) File containing KeyStore of type JKS. Mandatory if using java Keystore.
	private String jks_file;

	//(false, true) Adds timestamp to CMS signature. Only for CMS and PDF signature modes.
	private boolean TimeStamp_CMS_signature;

	//(false, true) Allows signing multiple files in a single XML enveloping signature.
	private boolean n_enveloping;

	//(false, true) Allows signing multiple files in a single XML detached signature.
	private boolean n_detached;

	//(OID string) Signature policy to include in CAdES/XAdES signature.
	private String signature_policy;

	//(B64 string) Signature policy hash to include in CAdES/XAdES signature.
	private String signature_policy_hash;

	//(String) Hash algorithm used to calculate signature policy hash.
	private int signature_policy_hash_algorithm;

	//(String) Signature policy qualifier to include in CAdES/XAdES signature.
	private String signature_policy_qualifier;

	//(OID string) Signer role to include in CAdES/XAdES signature.
	private String signer_role = null;

	//(OID String) Commitment Identifier and description to include in CAdES/XAdES signature
	private List<String> commitment_identifier = new ArrayList<String>();
	private List<String> commitment_description = new ArrayList<String>();

	//(URI String) commitment reference to include in CAdES/XAdES in case of various commitments or in case of one which not applies
	// over all signed objects
	private List<String> commitment_object_reference = new ArrayList<String>();

	//(false, true) Canonicalization transform with Comments (false by default = omit comments)
	private boolean canonicalizationWithComments;

	//(false, true) Canonicalization transform with Comments (false by default = omit comments)
	private boolean protectKeyInfo;

	//(value) space in KBytes to reserve
	private Integer pdf_reserved_space;

	//(name) PDF signature empty field to fulfill (must exist). Disables signature field selection panel.
	private String pdf_signature_field;

	//(false, true) True by default. If empty signature field exists forced visible.
	private boolean pdf_visible_signature;

	//(llx lly urx ury page_nr) Coordinates and page number of the visible rectangle containing the signature representation. Default coordinates (100, 100, 200, 200) page 1
	private HashMap<String, Integer> pdf_signature_rectangle;

	//(0, 1, 2, 3) Corresponds to document NOT CERTIFIED, CERTIFIED AND NO CHANGES ALLOWED, FORM FILLING ALLOWED, FORM FILLING AND ANNOTATIONS ALLOWED
	private int pdf_certification_level;

	//(value) Signature reason. Disables signature reason panel.
	private String pdf_reason;

	//(value) Signature location. Disables signature location panel.
	private String pdf_location;

	//(value) Signature image in Base64.
	private String pdf_signature_image;

	//(serverName port) Proxy settings.
	private HashMap<String, String> proxy_settings;

	//(CA1;CA2;...;CAn) CN of the issuer CA to be accepted. If empty or not specified, all issuer CAs will be accepted.
	private Vector<String> allowed_CAs;

	//(OID1;OID2;...OIDn) OIDs of the signing certificates to be accepted.
	private Vector<String> allowed_OIDs;

	//(name) Certificate alias to be used in signing process. Disables certificate selection panel.
	private String selected_alias;

	//(String) CN in the SubjectDistinguishedName of the selected certificate to use in signature if it is unique.
	private String selected_CN;

	//(String) Text to appear un SubjectDistinguishedName. Only certificats that contain the text will be selectable.
	private String subject_Text; 

	//(value) Text to appear in applet button. If empty or not specified, no button will appear and applet should be called via javascript.
	private String signButtonCaption;	

	//(R;G;B) RGB code to define the color to be used in the applet. 
	private Color appletBackground;

	//(Base64 string) Image to be used as a logo in Base64.
	private String appletLogo;

	// (value) Language. ca Catalan, es Spanish
	private String language;

	//TSA URL
	//URL de la TSA per generació de segells de temps RFC3161
	private String cmsts_tsa_url;
	//URL de la TSA per generació de segells de temps XML
	private String xmlts_tsa_url;

	//validació del certificat del signatari contra PSIS
	private boolean psis_validation = false;
	//valor requerit pel NIF del certiticat del signatari
	private String required_nif;

	// GUS: Mostra el contigut a signar
	private Boolean show_content;
	
	private int XAdES_type = 0;
	private int CAdES_type = 0; 

	private JButton signButton;

	/**
	 * Mètode que crida el navegador per iniciar l'applet. Es llegeixen els paràmetres per a
	 * carregar-lo.
	 */
	public void init() {

		// anulem el securityManager per a poder recuperar els paths
		// del fileDialog
		System.setSecurityManager(null);
		
		// posem el look and feel en funció del sistema per a que sigui més maco
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (Exception e) {
			// si no s'ha pogut forçar el look and feel en funció del sistema posem
			// el de java per defecte
			try {
				UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
			} catch (Exception e1) {
				// nothing to do
			}
		}

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				try {
					readParameters();

					//Inicialitzem el botó
					if(signButtonCaption != "") {
						signButton = new JButton(signButtonCaption);
						signButton.setLocation(0, 0);
						Dimension appletSize = getSize();
						signButton.setSize(appletSize);
						signButton.addActionListener(new ActionListener(){
							public void actionPerformed(ActionEvent e) {
								sign();
							}
						});
						setLayout(null);
						add(signButton);
					}
				} catch (FileNotFoundException e) {
					javascript("onLoadError", new String[] {"Init: " + e.getMessage()});
					e.printStackTrace();
				} catch (IOException e) {
					javascript("onLoadError", new String[] {"Init: " + e.getMessage()});
					e.printStackTrace();
				}

				javascript("onSignLoad", null);
			}
		});
	}

	/**
	 * 
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private void readParameters() throws FileNotFoundException, IOException {
		String param_value;

		// Params obligatoris
		param_value = getParameter("keystore_type");
		if (param_value != null)
			keystore_type = new Integer(param_value);
		else
			throw new RuntimeException("Tipus de magatzem de certificats desconegut");

		param_value = getParameter("signature_mode");
		if (param_value != null)
			signature_mode = new Integer(param_value);
		else
			throw new RuntimeException("Tipus de signatura desconeguda");

		param_value = getParameter("document_to_sign");
		if (param_value != null)
			document_to_sign = param_value;
		else
			document_to_sign = "";

		param_value = getParameter("hash_algorithm");
		if (param_value != null)
			hash_algorithm = new Integer(param_value);
		else
			hash_algorithm = SHA1;

		//Params opcionals
		param_value	= getParameter("js_event");
		if(param_value != null)
			js_event = new Boolean(param_value);
		else
			js_event = false;

		param_value = getParameter("js_multisignature_only_event");
		if(param_value != null){
			js_multisignature_only_event = new Boolean(param_value);
		}else{
			js_multisignature_only_event = false;
		}

		param_value	= getParameter("local_file");
		if(param_value != null)
			local_file = new Boolean(param_value);
		else
			local_file = doNotSaveLocalCopy;

		param_value	= getParameter("local_file_result_message");
		if(param_value != null)
			local_file_result_message = new Boolean(param_value);
		else
			local_file_result_message = showLocalCopyMessage;

		param_value = getParameter("doc_type");
		if(param_value != null)
			doc_type = new Integer(param_value);
		else
			doc_type = singleFile;

		param_value = getParameter("output_mode");
		if(param_value != null)
			output_mode = new Integer(param_value);
		else
			output_mode = base64;						

		param_value = getParameter("output_filename");
		if(param_value != null && !param_value.equals("")) {
			output_filename = new Vector<String>();
			StringTokenizer parser = new StringTokenizer(param_value, ";");
			while(parser.hasMoreTokens())
				output_filename.add(parser.nextToken());
		}

		param_value = getParameter("form_fill");
		if(param_value != null)
			form_fill = new Boolean(param_value);
		else
			form_fill = doNotupdateForm;

		param_value = getParameter("form_fill_form");
		if(param_value != null)
			form_fill_form = param_value;
		else
			form_fill_form = "appletCATCertForm";

		param_value = getParameter("form_fill_field");
		if(param_value != null)
			form_fill_field = param_value;
		else
			form_fill_field = "";

		param_value = getParameter("pkcs11_file");
		if(param_value != null)
			pkcs11_file = param_value;
		else
			pkcs11_file = "";		

		param_value = getParameter("pkcs12_file");
		if(param_value != null)
			pkcs12_file = param_value;
		else
			pkcs12_file = "";

		param_value = getParameter("jks_file");
		if(param_value != null)
			jks_file = param_value;
		else
			jks_file = "";

		param_value = getParameter("TimeStamp_CMS_signature");
		if(param_value != null)
			TimeStamp_CMS_signature = new Boolean(param_value);
		else
			TimeStamp_CMS_signature = false;

		param_value = getParameter("n_enveloping");
		if(param_value != null)
			n_enveloping = new Boolean(param_value);
		else
			n_enveloping = false;

		param_value = getParameter("n_detached");
		if(param_value != null)
			n_detached = new Boolean(param_value);
		else
			n_detached = false;

		param_value = getParameter("signature_policy");
		if(param_value != null)
			signature_policy = param_value;

		param_value = getParameter("signature_policy_hash");
		if(param_value != null)
			signature_policy_hash = param_value;

		param_value = getParameter("hash_algorithm");
		if (param_value != null)
			signature_policy_hash_algorithm = new Integer(param_value);
		else
			signature_policy_hash_algorithm = SHA1;

		param_value = getParameter("signature_policy_qualifier");
		if(param_value != null)
			signature_policy_qualifier = param_value;

		param_value = getParameter("signer_role");
		if(param_value != null)
			signer_role = param_value;

		param_value = getParameter("canonicalizationWithComments");
		if(param_value != null)
			canonicalizationWithComments = new Boolean(param_value);
		else
			canonicalizationWithComments = false;

		param_value = getParameter("protectKeyInfo");
		if(param_value != null)
			protectKeyInfo = new Boolean(param_value);
		else
			protectKeyInfo = false;

		param_value = getParameter("pdf_reserved_space");
		if(param_value != null)
			//pdf_reserved_space = new Integer("0x" + Integer.toHexString(new Integer(param_value)*2048+2));
			//pdf_reserved_space = Integer.parseInt((Integer.toHexString(new Integer(param_value)*2048+2)),16);
			pdf_reserved_space = Integer.parseInt((Integer.toHexString(new Integer(param_value)*1024)),16);
		param_value = getParameter("pdf_signature_field");
		if(param_value != null)
			pdf_signature_field = param_value;

		param_value = getParameter("pdf_visible_signature");
		if(param_value != null)
			pdf_visible_signature = new Boolean(param_value);
		else
			pdf_visible_signature = true;

		param_value = getParameter("pdf_signature_rectangle");
		if(param_value != null && !param_value.equals("")) {
			pdf_signature_rectangle = new HashMap<String, Integer>();
			StringTokenizer parser = new StringTokenizer(param_value);
			pdf_signature_rectangle.put("llx", new Integer(parser.nextToken()));
			pdf_signature_rectangle.put("lly", new Integer(parser.nextToken()));
			pdf_signature_rectangle.put("urx", new Integer(parser.nextToken()));
			pdf_signature_rectangle.put("ury", new Integer(parser.nextToken()));
			pdf_signature_rectangle.put("page_number", new Integer(parser.nextToken()));			
		}

		param_value = getParameter("pdf_certification_level");
		if(param_value != null)
			pdf_certification_level = new Integer(param_value);

		param_value = getParameter("pdf_reason");
		if(param_value != null)
			pdf_reason = param_value;

		param_value = getParameter("pdf_location");
		if(param_value != null)
			pdf_location = param_value;

		param_value = getParameter("pdf_signature_image");
		if(param_value != null)
			pdf_signature_image = param_value;

		param_value = getParameter("proxy_settings");
		if(param_value != null && !param_value.equals("")) {
			proxy_settings = new HashMap<String, String>();
			StringTokenizer parser = new StringTokenizer(param_value);
			proxy_settings.put("serverName", parser.nextToken());
			proxy_settings.put("serverPort", parser.nextToken());
			// Username & password
			try {
				proxy_settings.put("username", parser.nextToken());
				proxy_settings.put("password", parser.nextToken());
			} catch(NoSuchElementException e) {}
		}

		param_value = getParameter("allowed_CAs");
		if(param_value != null && !param_value.equals("")) {
			allowed_CAs = new Vector<String>();
			StringTokenizer parser = new StringTokenizer(param_value, ";");
			while(parser.hasMoreTokens())
				allowed_CAs.add(parser.nextToken());			
		}

		param_value = getParameter("allowed_OIDs");
		if(param_value != null && !param_value.equals("")) {
			allowed_OIDs = new Vector<String>();
			StringTokenizer parser = new StringTokenizer(param_value, ";");
			while(parser.hasMoreTokens())
				allowed_OIDs.add(parser.nextToken());			
		}

		param_value = getParameter("commitment_identifier");
		if(param_value != null && !param_value.equals("")){
			commitment_identifier = AppletUtils.getParams(param_value, ";");
		}

		param_value = getParameter("commitment_description");
		if(param_value != null && !param_value.equals("")){
			commitment_description = AppletUtils.getParams(param_value, ";");
		}

		param_value = getParameter("commitment_object_reference");
		if(param_value != null && !param_value.equals("")){
			commitment_object_reference = AppletUtils.getParams(param_value, ";");
		}

		param_value = getParameter("selected_alias");
		if(param_value != null)
			selected_alias = param_value;
		else
			selected_alias = "";

		param_value = getParameter("selected_CN");
		if(param_value != null)
			selected_CN = param_value;
		else selected_CN = "";

		param_value = getParameter("subject_Text");
		if(param_value != null)
			subject_Text = param_value;

		param_value = getParameter("signButtonCaption");
		if(param_value != null)
			signButtonCaption = param_value;
		else
			signButtonCaption = "";

		param_value = getParameter("appletBackground");
		if(param_value != null && !param_value.equals("")) {			
			StringTokenizer parser = new StringTokenizer(param_value, ";");
			Integer[] RGB = new Integer[3];
			RGB[0] = new Integer(parser.nextToken());
			RGB[1] = new Integer(parser.nextToken());
			RGB[2] = new Integer(parser.nextToken());
			appletBackground = new Color(RGB[0], RGB[1], RGB[2]);
		}
		else
			appletBackground = new Color(255, 255, 255); //default Windows: 238, 238, 238

		param_value	= getParameter("appletLogo");
		if(param_value != null)
			appletLogo = param_value;

		param_value = getParameter("language");
		if(param_value != null)
			language = param_value;		
		else
			language = CATALAN;

		param_value = getParameter("cmsts_tsa_url");
		if(param_value != null)
			cmsts_tsa_url = param_value;
		else
			cmsts_tsa_url = TsaUrl.PSIS_TSA_URL;

		param_value = getParameter("xmlts_tsa_url");
		if(param_value != null)
			xmlts_tsa_url = param_value;
		else
			xmlts_tsa_url = TsaUrl.PSIS_AVS_URL;

		param_value = getParameter("psis_validation");
		if(param_value != null)
			psis_validation = new Boolean(param_value);
		else
			psis_validation = false;

		param_value = getParameter("required_nif");
		if(param_value != null)
			required_nif = param_value;
		else
			required_nif = null;
		
		/* GUS */
		param_value = getParameter("show_content");
		if(param_value.equalsIgnoreCase("1") == true)
			show_content = true;
		else
			show_content = false;
		/* GUS */

		txt = ResourceBundle.getBundle("AppletSignatura", new Locale(language));

	}

	/**
	 * 
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private void addSecurityProviders() throws FileNotFoundException, IOException {
		//Providers de signatura XML / CMS
		switch(signature_mode) {
		case XMLdsig_enveloped: case XMLdsig_enveloping: case XMLdsig_detached: case XMLdsig_detached_hash:
			XAdES_type = XMLdsigGeneration.XMLdSIG;
			AddSunProvider.load();
			break;
		case XAdES_BES_enveloped: case XAdES_BES_enveloping: case XAdES_BES_detached: case XAdES_BES_detached_hash:
			XAdES_type = XMLdsigGeneration.XADES_BES;
			AddSunProvider.load();
			break;
		case XAdES_T_enveloped: case XAdES_T_enveloping: case XAdES_T_detached: case XAdES_T_detached_hash:
			XAdES_type = XMLdsigGeneration.XADES_T;
			AddSunProvider.load();
			break;
		case XAdES_C_enveloped: case XAdES_C_enveloping: case XAdES_C_detached: case XAdES_C_detached_hash:
			XAdES_type = XMLdsigGeneration.XADES_C;
			AddSunProvider.load();
			break;
		case CMS_attached: case CMS_detached: case CMS_detached_hash: case CMS_in_PDF:
			CAdES_type = CMSSignatureGeneration.CMS;
			AddBCProvider.load();
			break;
		case CAdES_BES_attached: case CAdES_BES_detached: case CAdES_BES_detached_hash: case CAdES_BES_in_PDF:
			CAdES_type = CMSSignatureGeneration.CAdES_BES;
			AddBCProvider.load();
			break;
		case CAdES_T_attached: case CAdES_T_detached: case CAdES_T_detached_hash: case CAdES_T_in_PDF:
			CAdES_type = CMSSignatureGeneration.CAdES_T;
			AddBCProvider.load();
			break;
		case CAdES_C_attached: case CAdES_C_detached: case CAdES_C_detached_hash: case CAdES_C_in_PDF:
			CAdES_type = CMSSignatureGeneration.CAdES_T;
			AddBCProvider.load();
			break;
		}

		// Providers de keystore
		// SunMSCAPI
		if (keystore_type == CertificateStore.MS_keystore)
			AddCAPIProvider.load();

		//La resta de keystores es carrega de forma dinàmica (Smartcard amb la impl. de Sun) o 
		//implícita(PKCS12, Java). ¿¿MOZILLA/MAC??
	}

	/**
	 * 
	 *
	 */
	@SuppressWarnings("unchecked")
	public void signFromJS() {
		AccessController.doPrivileged(new PrivilegedAction() {
			public Object run() {
				sign();
				return "";				
			}
		}
		);
	}

	/**
	 * Inicia el procés de signatura en funció dels paràmetres carregats.
	 *
	 */
	private void sign() {
		try {

			// Carreguem els providers
			// Els carreguem abans de signar, pq si es carreguen com fins ara desprès de llegir el 
			// paràmetres (readParameters) desprès si canvia algun parametre dinamicament ens podem trobar
			// variables malament instanciades (p.e XAdES_Level) a més de no tenir carregat el provider correcte
			addSecurityProviders();

			CertificateStore store = null;
			String alias = null;
			char[] PIN = null;
			String algorithm = null;
			String policy_algorithm = null;
			boolean signatureOK = false;
			String keyStore_file = null;

			//Darreres comprovacions abans de començar el procés de signatura
			if(keystore_type == CertificateStore.Smartcard_keystore){
				if(pkcs11_file.equals("")){
					throw new RuntimeException(txt.getString("missingPKCS11"));	
				}else{
					keyStore_file = pkcs11_file;
				}
			}else if(keystore_type == CertificateStore.PKCS12_keystore){
				if(pkcs12_file.equals("")){
					throw new RuntimeException(txt.getString("missingPKCS12"));	
				}else{
					keyStore_file = pkcs12_file;
				}
			}else if(keystore_type == CertificateStore.Java_keystore){
				if(jks_file.equals("")){
					throw new RuntimeException(txt.getString("missingJKS"));	
				}else{
					keyStore_file = jks_file;
				}
			}

			// Què hem de signar?
			// recollim el document a signar (documents si es tracta d'un directori), el hash ja el tindriem
			int signaturesToCreate = 1;
			Vector<byte[]> ftbsigned = new Vector<byte[]>();
			Vector<String> ftbsignedName = new Vector<String>();

			if(doc_type == singleFile)
				if(!document_to_sign.equals("")) {
					ftbsigned.add(Utils.streamToByteArray(new FileInputStream(document_to_sign)));
					ftbsignedName.add(document_to_sign);
					// signaturesToCreate es queda en 1
				}				
				else {
					Thread.sleep(1000);
					throw new RuntimeException(txt.getString("noDocumentToSign"));
				}					
			else if(doc_type == allFilesInDir) {
				StringTokenizer st = new StringTokenizer(document_to_sign,";");
				while(st.hasMoreTokens()) {
					String dirName = st.nextToken();
					File dir = new File(dirName);

					List<File> files = Utils.getFileListing(dir);

					if(files == null) {
						Thread.sleep(1000);
						throw new RuntimeException(txt.getString("emptyFolder"));
					}
					if(files.isEmpty()) {
						Thread.sleep(1000);
						throw new RuntimeException(txt.getString("emptyFolder"));
					}

					Iterator<File> filesIter = files.iterator();
					while(filesIter.hasNext()){
						File f = (File)filesIter.next();
						ftbsigned.add(Utils.streamToByteArray(new FileInputStream(f)));
						ftbsignedName.add(f.getAbsolutePath());
					}
				}
				if(!n_enveloping && !n_detached)
					signaturesToCreate = ftbsigned.size();
				// else signaturesToCreate es queda en 1
			}
			else if (doc_type == B64fileContent) {		
				if(!document_to_sign.equals("")) {
					List<String> params = AppletUtils.getParams(document_to_sign,";");
					for(String param : params){
						//ftbsigned.add(new BASE64Decoder().decodeBuffer(param));	
						ftbsigned.add(javax.xml.bind.DatatypeConverter.parseBase64Binary(param));
					}
					if(!n_enveloping && !n_detached)	
						signaturesToCreate = ftbsigned.size();
					// sino
					// signaturesToCreate es queda en 1
				}
				else {
					Thread.sleep(1000);
					throw new RuntimeException(txt.getString("noDocumentToSign"));
				}					
			}else if(doc_type == fileList) {
				if(!document_to_sign.equals("")) {
					StringTokenizer st = new StringTokenizer(document_to_sign,";");
					while(st.hasMoreTokens()) {
						String name = st.nextToken();
						ftbsigned.add(Utils.streamToByteArray(new FileInputStream(name)));
						ftbsignedName.add(name);
					}
				}
				else {
					Thread.sleep(1000);
					throw new RuntimeException(txt.getString("noDocumentToSign"));	
				}					
				if(!n_enveloping && !n_detached)						
					signaturesToCreate = ftbsigned.size();
				// else signaturesToCreate es queda en 1
			}
			else if(doc_type == urlFile) {
				if(!document_to_sign.equals("")) {
					StringTokenizer st = new StringTokenizer(document_to_sign,";");
					Vector<URL> fileURL = new Vector<URL>();
					HTTPSender downloader = new HTTPSender(proxy_settings);

					while(st.hasMoreTokens())
						fileURL.add(new URL(st.nextToken()));

					for (int i =0; i < fileURL.size(); i++) {
						InputStream stream = downloader.getMethod(fileURL.get(i));

						if (stream == null) {
							Thread.sleep(1000);
							throw new RuntimeException(txt.getString("downloadProblem"));	
						} else {
							DownloadProgressBar bar = new DownloadProgressBar(stream, i+1, fileURL.size(), downloader.returnCurrentContentLength(), appletBackground);
							ColorJOptionPane pane = new ColorJOptionPane(appletBackground);
							Object[] options = new Object[] {bar};
							pane.prepareProgressDialog(null, bar, "", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]);
							bar.startDownload();
							if(pane.showProgressDialog() == JOptionPane.CLOSED_OPTION) {
								if(!bar.isDone()) {
									Thread.sleep(1000);
									throw new RuntimeException(txt.getString("downloadCancel"));
								}
								else
									ftbsigned.add(bar.getDownloadedFile());
							}
							//							else
							//								ftbsigned.add(bar.getDownloadedFile());
							// else signaturesToCreate es queda en 1	
						}
					}
					if(!n_enveloping && !n_detached)	
						signaturesToCreate = ftbsigned.size();
				}
				else
					throw new RuntimeException(txt.getString("noDocumentToSign"));				
			}
			else if(doc_type == hashDoc) {
				if(!document_to_sign.equals("")) {
					StringTokenizer st = new StringTokenizer(document_to_sign,";");
					while(st.hasMoreTokens())
						//ftbsigned.add(new BASE64Decoder().decodeBuffer(st.nextToken()));
						ftbsigned.add(javax.xml.bind.DatatypeConverter.parseBase64Binary(st.nextToken()));
				}
				else {
					Thread.sleep(1000);
					throw new RuntimeException(txt.getString("noDocumentToSign"));
				}
				if(!n_detached)
					signaturesToCreate = ftbsigned.size();
				// else signaturesToCreate es queda en 1				
			}
			else if(doc_type == form) {
				if(!document_to_sign.equals("")) {
					if(XAdES_type == 0) // Signatura CMS/CAdES
						ftbsigned.add(document_to_sign.getBytes());
					else // Signatura XMLdsig/XAdES
						ftbsigned.add(document_to_sign.getBytes("utf-8"));
				}

				// signaturesToCreate es queda en 1
				else {
					Thread.sleep(1000);
					throw new RuntimeException(txt.getString("noDocumentToSign"));
				}
			}

			// Algoritme de Hash a utilitzar, assignem l'OID pertinent
			switch(hash_algorithm) {
			case SHA1: algorithm = SHA1ID;
			break;
			case SHA256: algorithm = SHA256ID;
			break;
			case SHA512: algorithm = SHA512ID;
			break;
			}
			switch(signature_policy_hash_algorithm) {
			case SHA1: policy_algorithm = SHA1ID;
			break;
			case SHA256: policy_algorithm = SHA256ID;
			break;
			case SHA512: policy_algorithm = SHA512ID;
			break;
			}

			// Diàleg selecció de certificat en funció del tipus d'store a utilitzar
			CertSelectionDialog dialog = new CertSelectionDialog(keystore_type, keyStore_file, allowed_CAs, allowed_OIDs, 
					selected_alias, selected_CN, subject_Text, appletBackground, appletLogo, txt, psis_validation, show_content,
					document_to_sign, doc_type);

			// Inici procés signatura
			if (dialog.run()) {
				PIN = dialog.getPIN();
				store = dialog.getStore();
				alias = dialog.getSelectedAlias();

				// Signatures generades per a un event específic i recuperar-les totes de cop
				String[] multiSignature = new String[signaturesToCreate];

				//barra de progrés
				//				ProgressStatePane statePane = new ProgressStatePane(appletBackground);
				//				ColorJOptionPane pane = new ColorJOptionPane(appletBackground);
				//				Object[] optionss = new Object[] {statePane};
				//				pane.prepareProgressDialog(null, statePane, "", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, optionss, optionss[0]);
				//				statePane.startProgress();

				for(int i = 0; i<multiSignature.length; i++) {

					//Signem segons el tipus seleccionat
					//statePane.updateStatus(1, txt.getString("generating.signature"));

					byte[] output = signem(i, ftbsigned, store, alias, PIN, algorithm, policy_algorithm);
					if (output != null)
					{
						//statePane.updateStatus(2, txt.getString("finished.signature"));
						String tmpStr = getJSSignature(i, output, multiSignature);
						// Si s'ha d'actualitzar el form...
						if(form_fill) {
							//statePane.updateStatus(3, txt.getString("filling.form"));
							omplirFormulari(tmpStr, output);
						}

						// Si s'ha de crear document en local...
						if(local_file) {
							//statePane.updateStatus(4, txt.getString("saving.file"));

							File file;
							if(n_enveloping || n_detached || doc_type == B64fileContent || doc_type == urlFile || doc_type == hashDoc || doc_type == form)
								// 1 sol document de sortida, no tenim nom del doc original o casos sense nom (url, b64, hash o form)
								file = createOuptutFile(null, i);
							else
								file = createOuptutFile(ftbsignedName.get(i), i);

							// Substituim o afegim si no hi ha element en aquesta posició
							if (ftbsignedName.size() == i)
								ftbsignedName.add(file.getAbsolutePath());
							else
								ftbsignedName.set(i, file.getAbsolutePath());							
							FileOutputStream out = new FileOutputStream(file);
							out.write(output);
							out.close();

							// Missatge amb totes les signatures generades
							if(local_file_result_message){
								if(i == multiSignature.length - 1) {
									Object[] options = {txt.getString("okButton")};
									String files = "";
									if(doc_type == allFilesInDir)
										files += document_to_sign;
									else
										for (int j = 0; j<multiSignature.length; j++)
											files += ftbsignedName.get(j)+ "\n";
									new ColorJOptionPane(appletBackground).showCATCertDialog(this, txt.getString("signatureGenerated") + files, txt.getString("info"),
											JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);
								}
							}
						}
						signatureOK = false;
					}
					else
					{
						javascript("onSignCancel", null);
					}					
				}

				//				if(statePane.close() == JOptionPane.CLOSED_OPTION) {
				//				//if(pane.showProgressDialog() == JOptionPane.CLOSED_OPTION) {
				//					if(!statePane.isDone()) {
				//						Thread.sleep(1000);
				//						throw new RuntimeException(txt.getString("processCancel"));	
				//					}
				//				}
			}
			else {
				// L'usuari ha cancel·lat
				// Provoca problemes a IE7 si es crida l'applet a través de Javascript! (concurrència, IE es penja!!)
				// Adormim el procés 1 segon per a solucionar-ho.
				Thread.sleep(1000);
				javascript("onSignCancel", null);
			}
		} catch (HeadlessException e) {
			javascript("onLoadError", new String[] {"UI: " + e.getMessage()});
			e.printStackTrace();
		} catch (CMSSignatureGenerationException e) {
			javascript("onSignError", new String[] {"CMS: " + e.getMessage()});
			e.printStackTrace();
		} catch (PDFSignatureGenerationException e) {
			javascript("onSignError", new String[] {"PDF: " + e.getMessage()});
			e.printStackTrace();
		} catch (XMLdsigGenerationException e) {
			javascript("onSignError", new String[] {"XML: " + e.getMessage()});
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			javascript("onSignError", new String[] {"File: " + e.getMessage()});
			e.printStackTrace();
		} catch (IOException e) {
			javascript("onSignError", new String[] {"IO: " + e.getMessage()});
			e.printStackTrace();
		} catch (CertificateStoreException e) {
			javascript("onLoadError", new String[] {"Certificate: " + e.getMessage()});
			e.printStackTrace();
		} catch (RuntimeException e) {
			javascript("onSignError", new String[] {"Runtime error: " + e.getMessage()});
			e.printStackTrace();
		}catch (NoSuchAlgorithmException e) {
			javascript("onSignError", new String[] {e.getMessage()});
			e.printStackTrace();
		} catch (PSISValidationException e) {
			String err = txt.getString(e.getMessage());
			if(e.getMessage().equalsIgnoreCase("psis.cert.nif.invalid"))
				err+=" "+required_nif;
			javascript("onSignError", new String[] {err});
			e.printStackTrace();
		} catch (InterruptedException e) {
			javascript("onSignError", new String[] {e.getMessage()});
			e.printStackTrace();
		} catch (HTTPSenderException e) {
			javascript("onSignError", new String[] {e.getMessage()});
			e.printStackTrace();
		} catch (Throwable e) {
			javascript("onSignError", new String[] {"Unknown: " + e.getMessage()});
			e.printStackTrace();
		}

	}

	/**
	 * 
	 * @param filename
	 * @param index
	 * @return
	 */
	private File createOuptutFile(String filename, int index){

		// Nom per defecte (sense extensió) a la carpeta CATCert dins de la carpeta personal de l'usuari
		if(filename == null) {
			// Si no existeix la carpeta, la creem a la userhome
			File localDir = new File(CATCert);
			if (!localDir.exists())
				localDir.mkdir();
			// Nom del document amb el path de CATCert
			filename = CATCert + System.getProperty("file.separator") + "document_" + index;
		}			

		// Mirem si hi ha nom decidit per paràmetre...
		if(output_filename != null)
			try{
				filename = output_filename.get(index);
			}catch(IndexOutOfBoundsException e){
				// s'ha afegit la possibilitat de donar més d'un fitxer en base64, si la persona no configura més d'un nom
				// tindrem un indexOutOfBounds!! allora che cazzo facciamo??
				filename = output_filename.lastElement() + index; 
			}

		// ... sinó, nom per defecte + extensió que toqui
		else
			switch(output_mode){
			case binary:
			case base64:
				filename = filename + "_signat.p7b";
				break;
			case xml:
				filename = filename + "_signat.xml";
				break;
			default: //pdf
				filename = filename + "_signat.pdf";
				break;
			}
		return new File(filename);
	}

	/**
	 * 
	 * @param name
	 * @param value
	 */
	public void set(String name, String value) {		
		if(name.equals("keystore_type"))
			keystore_type = new Integer(value);
		else if(name.equals("signature_mode"))
			signature_mode = new Integer(value);
		else if(name.equals("document_to_sign"))
			document_to_sign = value;
		else if(name.equals("hash_algorithm"))
			hash_algorithm = new Integer(value);
		else if(name.equals("js_event"))
			js_event = new Boolean(value);
		else if(name.equals("js_multisignature_only_event"))
			js_multisignature_only_event = new Boolean(value);
		else if(name.equals("local_file"))
			local_file = new Boolean(value);
		else if(name.equals("doc_type"))
			doc_type = new Integer(value);
		else if(name.equals("output_mode"))
			output_mode = new Integer(value);
		else if(name.equals("form_fill"))
			form_fill = new Boolean(value);
		else if(name.equals("form_fill_form"))
			form_fill_form = value;
		else if(name.equals("form_fill_field"))
			form_fill_field = value;
		else if(name.equals("output_filename")) {
			StringTokenizer parser = new StringTokenizer(value, ";");
			output_filename = new Vector<String>();
			while(parser.hasMoreTokens())
				output_filename.add(parser.nextToken());
		}
		else if(name.equals("pkcs11_file"))
			pkcs11_file = value;
		else if(name.equals("pkcs12_file"))
			pkcs12_file = value;
		else if(name.equals("jks_file"))
			jks_file = value;
		else if(name.equals("TimeStamp_CMS_signature"))
			TimeStamp_CMS_signature = new Boolean(value);
		else if(name.equals("n_enveloping"))
			n_enveloping = new Boolean(value);
		else if(name.equals("n_detached"))					
			n_detached = new Boolean(value);
		else if(name.equals("signature_policy"))
			signature_policy = value;
		else if(name.equals("signature_policy_hash"))
			signature_policy_hash = value;
		else if(name.equals("signature_policy_hash_algorithm"))
			signature_policy_hash_algorithm = new Integer(value);
		else if(name.equals("signature_policy_qualifier"))
			signature_policy_qualifier = value;
		else if(name.equals("signer_role"))
			signer_role = value;
		else if(name.equals("canonicalizationWithComments"))
			canonicalizationWithComments = new Boolean(value);
		else if(name.equals("protectKeyInfo"))
			protectKeyInfo = new Boolean(value);
		else if(name.equals("pdf_reserved_space"))			
			//pdf_reserved_space = new Integer("0x" + Integer.toHexString(new Integer(value)*2048+2));
			//pdf_reserved_space = Integer.parseInt((Integer.toHexString(new Integer(value)*2048+2)),16);
			pdf_reserved_space = Integer.parseInt((Integer.toHexString(new Integer(value)*1024)),16);
		else if(name.equals("pdf_signature_field"))
			pdf_signature_field = value;
		else if(name.equals("pdf_signature_rectangle")) {
			StringTokenizer parser = new StringTokenizer(value);
			pdf_signature_rectangle = new HashMap<String, Integer>();
			pdf_signature_rectangle.put("llx", new Integer(parser.nextToken()));
			pdf_signature_rectangle.put("lly", new Integer(parser.nextToken()));
			pdf_signature_rectangle.put("urx", new Integer(parser.nextToken()));
			pdf_signature_rectangle.put("ury", new Integer(parser.nextToken()));
			pdf_signature_rectangle.put("page_number", new Integer(parser.nextToken()));			
		}
		else if(name.equals("pdf_certification_level"))
			pdf_certification_level = new Integer(value);
		else if(name.equals("pdf_reason"))
			pdf_reason = value;
		else if(name.equals("pdf_location"))
			pdf_location = value;
		else if(name.equals("pdf_signature_image"))
			pdf_signature_image = value;
		else if(name.equals("proxy_settings")) {
			StringTokenizer parser = new StringTokenizer(value);
			proxy_settings = new HashMap<String, String>();
			proxy_settings.put("serverName", parser.nextToken());
			proxy_settings.put("serverPort", parser.nextToken());
			try {
				proxy_settings.put("username", parser.nextToken());
				proxy_settings.put("password", parser.nextToken());
			} catch(NoSuchElementException e) {}
		}
		else if(name.equals("allowed_CAs")){			
			StringTokenizer parser = new StringTokenizer(value, ";");
			allowed_CAs = new Vector<String>();
			while(parser.hasMoreTokens())
				allowed_CAs.add(parser.nextToken());
		}
		else if(name.equals("allowed_OIDs")){			
			StringTokenizer parser = new StringTokenizer(value, ";");
			allowed_OIDs = new Vector<String>();
			while(parser.hasMoreTokens())
				allowed_OIDs.add(parser.nextToken());
		}
		else if(name.equals("selected_alias"))
			selected_alias = value;
		else if(name.equals("selected_CN"))
			selected_CN = value;
		else if(name.equals("subject_Text"))
			subject_Text = value;
		else if(name.equals("signButtonCaption")){
			signButtonCaption = value;
		}
		else if(name.equals("appletBackground")){			
			StringTokenizer parser = new StringTokenizer(value, ";");
			Integer[] RGB = new Integer[3];
			RGB[0] = new Integer(parser.nextToken());
			RGB[1] = new Integer(parser.nextToken());
			RGB[2] = new Integer(parser.nextToken());
			appletBackground = new Color(RGB[0], RGB[1], RGB[2]);
		}
		else if(name.equals("appletLogo"))
			appletLogo = value;
		else if(name.equals("language")) {
			language = value;
			txt = ResourceBundle.getBundle("AppletSignatura", new Locale(language));
		}
		else if(name.equals("cmsts_tsa_url")){
			cmsts_tsa_url = value;
		}
		else if(name.equals("xmlts_tsa_url")){
			xmlts_tsa_url = value;
		}
		else if(name.equals("commitment_identifier")){
			commitment_identifier = AppletUtils.getParams(value, ";");
		}
		else if(name.equals("commitment_description")){
			commitment_description = AppletUtils.getParams(value, ";");
		}
		else if(name.equals("commitment_object_reference")){
			commitment_object_reference = AppletUtils.getParams(value, ";");
		}
	}

	/**
	 * 
	 * @param function
	 * @param args
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public Object javascript(String function, String args[]) throws RuntimeException
	{
		try
		{
			Vector list = new Vector();
			if(args != null)
			{
				for(int i = 0; i < args.length; i++)
					list.addElement(args[i]);
			}
			if(list.size() > 0)
			{				
				Object objs[] = new Object[list.size()];
				list.copyInto(objs);
				return JSObject.getWindow(this).call(function, objs);
			} else{
				return JSObject.getWindow(this).call(function, new Object[0]);
			}
		}
		catch(UnsatisfiedLinkError e){
			e.printStackTrace();
			throw new RuntimeException(e + "\nFunction: " + function);
		}
		catch(Throwable e){
			e.printStackTrace();
			throw new RuntimeException(e + "\nFunction: " + function);
		}
	}

	//	public boolean runSignature(String[] multiSignature, Vector<byte[]> ftbsigned, Vector<String> ftbsignedName, CertificateStore store, String alias, char[] PIN, String algorithm, String policy_algorithm)
	//	//public boolean runSignature(ProgressStatePane statePane, String[] multiSignature, Vector<byte[]> ftbsigned, Vector<String> ftbsignedName, CertificateStore store, String alias, char[] PIN, String algorithm, String policy_algorithm) 
	//	{
	//		
	//		boolean signatureOK = false;
	//		// i generem la signatura/signatures si hi ha més d'un document				
	//		try {
	//
	//			ProgressStatePane statePane = new ProgressStatePane(appletBackground, this, 
	//					multiSignature, 
	//					ftbsigned, 
	//					ftbsignedName, 
	//					store, 
	//					alias, 
	//					PIN, 
	//					algorithm, 
	//					policy_algorithm,
	//					psis_validation);
	//			ColorJOptionPane pane = new ColorJOptionPane(appletBackground);
	//			Object[] optionss = new Object[] {statePane};
	//			pane.prepareProgressDialog(null, statePane, "", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, optionss, optionss[0]);
	//			statePane.startProgress();
	//
	//			for(int i = 0; i<multiSignature.length; i++) {
	//	
	//				//Signem segons el tipus seleccionat
	//				statePane.updateStatus(1, txt.getString("generating.signature"));
	//				//TODO
	//				byte[] output = signem(i, ftbsigned, store, alias, PIN, algorithm, policy_algorithm);
	//				if (output != null)
	//				{
	//					statePane.updateStatus(2, txt.getString("finished.signature"));
	//					String tmpStr = getJSSignature(i, output, multiSignature);
	//					// Si s'ha d'actualitzar el form...
	//					if(form_fill) {
	//						statePane.updateStatus(3, txt.getString("filling.form"));
	//						omplirFormulari(tmpStr, output);
	//					}
	//	
	//					// Si s'ha de crear document en local...
	//					if(local_file) {
	//						statePane.updateStatus(4, txt.getString("saving.file"));
	//						File file;
	//	
	//						if(n_enveloping || n_detached || doc_type == B64fileContent || doc_type == urlFile || doc_type == hashDoc || doc_type == form)
	//							// 1 sol document de sortida, no tenim nom del doc original o casos sense nom (url, b64, hash o form)
	//							file = createOuptutFile(null, i);
	//						else
	//							file = createOuptutFile(ftbsignedName.get(i), i);
	//	
	//						// Substituim o afegim si no hi ha element en aquesta posició
	//						if (ftbsignedName.size() == i)
	//							ftbsignedName.add(file.getAbsolutePath());
	//						else
	//							ftbsignedName.set(i, file.getAbsolutePath());							
	//						FileOutputStream out = new FileOutputStream(file);
	//						out.write(output);
	//						out.close();
	//	
	//						// Missatge amb totes les signatures generades
	//						if(local_file_result_message){
	//							if(i == multiSignature.length - 1) {
	//								Object[] options = {txt.getString("okButton")};
	//								String files = "";
	//								if(doc_type == allFilesInDir)
	//									files += document_to_sign;
	//								else
	//									for (int j = 0; j<multiSignature.length; j++)
	//										files += ftbsignedName.get(j)+ "\n";
	//								new ColorJOptionPane(appletBackground).showCATCertDialog(this, txt.getString("signatureGenerated") + files, txt.getString("info"),
	//										JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);
	//							}
	//						}
	//					}
	//					signatureOK = false;
	//				}
	//				else
	//				{
	//					javascript("onSignCancel", null);
	//				}
	//				
	//			}
	//			
	//			statePane.updateStatus(5, "Fin");
	//			System.out.println(statePane.isDone());
	//			statePane.transferFocus();
	//			remove(statePane);
	//			
	//			if(pane.showProgressDialog() == JOptionPane.CLOSED_OPTION) {
	//				if(!statePane.isDone()) {
	//					Thread.sleep(1000);
	//					throw new RuntimeException(txt.getString("processCancel"));	
	//				}
	//			}
	//			
	//		} catch (NoSuchAlgorithmException e) {
	//			javascript("onSignError", new String[] {e.getMessage()});
	//			e.printStackTrace();
	//		} catch (CMSSignatureGenerationException e) {
	//			javascript("onSignError", new String[] {"CMS: " + e.getMessage()});
	//			e.printStackTrace();
	//		} catch (IOException e) {
	//			javascript("onSignError", new String[] {e.getMessage()});
	//			e.printStackTrace();
	//		} catch (PDFSignatureGenerationException e) {
	//			javascript("onSignError", new String[] {"PDF: " + e.getMessage()});
	//			e.printStackTrace();
	//		} catch (XMLdsigGenerationException e) {
	//			javascript("onSignError", new String[] {"XML: " + e.getMessage()});
	//			e.printStackTrace();
	//		} catch (CertificateEncodingException e) {
	//			javascript("onSignError", new String[] {"CMS: " + e.getMessage()});
	//			e.printStackTrace();
	//		} catch (PSISValidationException e) {
	//			String err = txt.getString(e.getMessage());
	//			if(e.getMessage().equalsIgnoreCase("psis.cert.nif.invalid"))
	//				err+=" "+required_nif;
	//			javascript("onSignError", new String[] {err});
	//			e.printStackTrace();
	//		} catch (InterruptedException e) {
	//			javascript("onSignError", new String[] {e.getMessage()});
	//			e.printStackTrace();
	//		} catch (HTTPSenderException e) {
	//			javascript("onSignError", new String[] {e.getMessage()});
	//			e.printStackTrace();
	//		}
	//		return signatureOK;
	//	}

	private byte[] signem(int i, Vector<byte[]> ftbsigned, CertificateStore store, String alias, char[] PIN, String algorithm, String policy_algorithm)
	//private byte[] signem(int i, Vector<byte[]> ftbsigned, CertificateStore store, String alias, char[] PIN, String algorithm, String policy_algorithm, ProgressStatePane state) 
	throws CMSSignatureGenerationException, IOException, PDFSignatureGenerationException, XMLdsigGenerationException, NoSuchAlgorithmException, CertificateEncodingException, PSISValidationException
	{
		byte[] output = null;

		switch (signature_mode) {
		case CMS_attached: case CAdES_BES_attached: case CAdES_T_attached: case CAdES_C_attached:
			if(output_mode == binary)							
				output = CMSSignatureGeneration.sign(ftbsigned.get(i), store.getStore(), alias, PIN, true, TimeStamp_CMS_signature, CAdES_type, null, algorithm, signature_policy, signature_policy_hash, policy_algorithm, signer_role, commitment_identifier, proxy_settings, cmsts_tsa_url, psis_validation, required_nif);						
			else
				output = CMSSignatureGeneration.signToBase64(ftbsigned.get(i), store.getStore(), alias, PIN, true, TimeStamp_CMS_signature, CAdES_type, null, algorithm, signature_policy, signature_policy_hash, policy_algorithm, signer_role, commitment_identifier, proxy_settings, cmsts_tsa_url, psis_validation, required_nif);
			break;

		case CMS_detached: case CAdES_BES_detached: case CAdES_T_detached: case CAdES_C_detached:
			if(output_mode == binary)							
				output = CMSSignatureGeneration.sign(ftbsigned.get(i), store.getStore(), alias, PIN, false, TimeStamp_CMS_signature, CAdES_type, null, algorithm, signature_policy, signature_policy_hash, policy_algorithm, signer_role, commitment_identifier, proxy_settings, cmsts_tsa_url, psis_validation, required_nif);
			else
				output = CMSSignatureGeneration.signToBase64(ftbsigned.get(i), store.getStore(), alias, PIN, false, TimeStamp_CMS_signature, CAdES_type, null, algorithm, signature_policy, signature_policy_hash, policy_algorithm, signer_role, commitment_identifier, proxy_settings, cmsts_tsa_url, psis_validation, required_nif);
			break;

		case CMS_detached_hash: case CAdES_BES_detached_hash: case CAdES_T_detached_hash: case CAdES_C_detached_hash:
			if(output_mode == binary)
				output = CMSSignatureGeneration.signHash(ftbsigned.get(i), store.getStore(), alias, PIN, TimeStamp_CMS_signature, CAdES_type, null, algorithm, signature_policy, signature_policy_hash, policy_algorithm, signer_role, commitment_identifier, proxy_settings, cmsts_tsa_url, psis_validation, required_nif);
			else
				output = CMSSignatureGeneration.signHashToBase64(ftbsigned.get(i), store.getStore(), alias, PIN, TimeStamp_CMS_signature, CAdES_type, null, algorithm, signature_policy, signature_policy_hash, policy_algorithm, signer_role, commitment_identifier, proxy_settings, cmsts_tsa_url, psis_validation, required_nif);
			break;

		case CMS_in_PDF: case CAdES_BES_in_PDF: case CAdES_T_in_PDF: case CAdES_C_in_PDF:
			output_mode = pdf;
			PdfInputsDialog pdfDialog = new PdfInputsDialog(pdf_visible_signature, pdf_signature_field, pdf_certification_level, TimeStamp_CMS_signature, pdf_reason, pdf_location, pdf_signature_image, pdf_signature_rectangle, appletBackground, appletLogo, txt);
			output = PDFSignatureGeneration.sign(ftbsigned.get(i), store.getStore(), alias, PIN, CAdES_type, pdf_reserved_space, algorithm, pdfDialog, signature_policy, signature_policy_hash, policy_algorithm, signer_role, commitment_identifier, proxy_settings, cmsts_tsa_url, psis_validation, required_nif);
			//Controlem cancel.lació usuari en diàleg PDF
			break;

		case XMLdsig_enveloped: case XAdES_BES_enveloped: case XAdES_T_enveloped: case XAdES_C_enveloped:
			output_mode = xml;
			output = XMLdsigGeneration.sign(ftbsigned.get(i), store.getStore(), alias, PIN, XMLdsigGeneration.enveloped, algorithm, XAdES_type, signature_policy, signature_policy_hash, policy_algorithm, signature_policy_qualifier, signer_role, commitment_identifier, commitment_description, commitment_object_reference, canonicalizationWithComments, protectKeyInfo, proxy_settings, xmlts_tsa_url, psis_validation, required_nif);
			break;

		case XMLdsig_enveloping: case XAdES_BES_enveloping: case XAdES_T_enveloping: case XAdES_C_enveloping:
			output_mode = xml;
			if(n_enveloping)
				output = XMLdsigGeneration.sign_nEnveloping(ftbsigned, store.getStore(), alias, PIN, algorithm, XAdES_type, signature_policy, signature_policy_hash, policy_algorithm, signature_policy_qualifier, signer_role, commitment_identifier, commitment_description, commitment_object_reference, canonicalizationWithComments, protectKeyInfo, proxy_settings, xmlts_tsa_url, psis_validation, required_nif);
			else
				output = XMLdsigGeneration.sign(ftbsigned.get(i), store.getStore(), alias, PIN, XMLdsigGeneration.enveloping, algorithm, XAdES_type, signature_policy, signature_policy_hash, policy_algorithm, signature_policy_qualifier, signer_role, commitment_identifier, commitment_description, commitment_object_reference, canonicalizationWithComments, protectKeyInfo, proxy_settings, xmlts_tsa_url, psis_validation, required_nif);
			break;

		case XMLdsig_detached: case XAdES_BES_detached: case XAdES_T_detached: case XAdES_C_detached:
			output_mode = xml;
			if(n_detached)
				output = XMLdsigGeneration.sign_nDetached(XMLdsigGeneration.calculateVectorContentsHash(ftbsigned, algorithm), store.getStore(), alias, PIN, algorithm, XAdES_type, signature_policy, signature_policy_hash, policy_algorithm, signature_policy_qualifier, signer_role, commitment_identifier, commitment_description, commitment_object_reference, canonicalizationWithComments, protectKeyInfo, proxy_settings, xmlts_tsa_url, psis_validation, required_nif);
			else
				output = XMLdsigGeneration.sign(ftbsigned.get(i), store.getStore(), alias, PIN, XMLdsigGeneration.detached_document, algorithm, XAdES_type, signature_policy, signature_policy_hash, policy_algorithm, signature_policy_qualifier, signer_role, commitment_identifier, commitment_description, commitment_object_reference, canonicalizationWithComments, protectKeyInfo, proxy_settings, xmlts_tsa_url, psis_validation, required_nif);
			break;

		case XMLdsig_detached_hash: case XAdES_BES_detached_hash: case XAdES_T_detached_hash: case XAdES_C_detached_hash:
			output_mode = xml;
			if(n_detached)
				output = XMLdsigGeneration.sign_nDetached(ftbsigned, store.getStore(), alias, PIN, algorithm, XAdES_type, signature_policy, signature_policy_hash, policy_algorithm, signature_policy_qualifier, signer_role, commitment_identifier, commitment_description, commitment_object_reference, canonicalizationWithComments, protectKeyInfo, proxy_settings, xmlts_tsa_url, psis_validation, required_nif);
			else {
				Vector<byte[]> tmp = new Vector<byte[]>();
				tmp.add(ftbsigned.get(i));
				output = XMLdsigGeneration.sign_nDetached(tmp, store.getStore(), alias, PIN, algorithm, XAdES_type, signature_policy, signature_policy_hash, policy_algorithm, signature_policy_qualifier, signer_role, commitment_identifier, commitment_description, commitment_object_reference, canonicalizationWithComments, protectKeyInfo, proxy_settings, xmlts_tsa_url, psis_validation, required_nif);
			}
			break;
		default:
			break;
		}

		return output;
	}

	private String getJSSignature(int i, byte[] output, String[] multiSignature) throws UnsupportedEncodingException
	{
		String tmpStr = new String(output, "utf-8");

		// Retornem la signatura via event JavaScript
		if(js_event) {
			// Codifiquem a Base64 (degut a problemes amb PDFs, codificació binaria).
			// No es fa en el cas de que ja ho estigui o que es tracti d'un XML.
			if (output_mode != base64 && output_mode != xml)
				//tmpStr = new BASE64Encoder().encode(output);
				tmpStr = Utils.printBase64Binary(output);

			javascript("onSignOK", new String[] {tmpStr});
			multiSignature[i] = new String(tmpStr);

			// Event amb totes les signatures generades
			if(i == multiSignature.length - 1){
				if(js_multisignature_only_event){
					javascript("onMultiSignOK", new String[] {"only event"});
				}else{
					javascript("onMultiSignOK", multiSignature);	
				}
			}		
		}

		return tmpStr;
	}

	private void omplirFormulari(String tmpStr, byte[] output)
	{

		JSObject window = JSObject.getWindow(this);
		JSObject doc = (JSObject)window.getMember("document");
		JSObject mainForm = (JSObject)doc.getMember(form_fill_form);
		JSObject signatureField = (JSObject) mainForm.getMember(form_fill_field);
		// Codifiquem a Base64 (degut a problemes amb PDFs, codificació binaria).
		// No es fa en el cas de que ja ho estigui o que es tracti d'un XML.
		if (output_mode != base64 && output_mode != xml)
			//tmpStr = new BASE64Encoder().encode(output);
			tmpStr = Utils.printBase64Binary(output);
		signatureField.setMember("value", tmpStr);
	}


	// ************************** CODE TO SOLVE FAKEPATH ************************************ //
	// Aquest codi crea un dialeg per a carregar un fitxer per a evitar els problemes del
	// fakepath deguts a la nova configuració de seguretat que apliquen els navegadors
	private XFileDialog dlg = null;

	// ES FA EN DOS MÈTODES PER PROBLEMES AMB DIVERSOS NAVEGADORS A L'HORA DE PASSAR UN PARÀMETRE
	
	public void openFileDialog(){
		openDialog(false);
	}
	
	public void openFolderDialog(){
		openDialog(true);
	}
	
	/**
	 * Displays a file dialog, calling the specified JavaScript functions when
	 * the user selects a file or cancels the dialog.
	 * 
	 * @param onFile The name of the function to call when the user selects a
	 * file.
	 * @param onCancel The name of the function to call when the user cancels
	 * a dialog selection.
	 */
	private void openDialog(boolean isFolder)
	{		
		if(dlg == null){
			dlg=new XFileDialog(AppletSignatura.this);	
		}

		dlg.setTitle("CATCert - Eina web de signatura-e"); 
		String content = null;
		String folder = null;

		if(isFolder){
			content = dlg.getFolder();		
		}else{
			content =dlg.getFile(); 
			folder = dlg.getDirectory();
		}

		dlg.dispose();

		if (content == null || content.length() == 0)
		{
			callJavaScript("onFileCancel");
		}
		else
		{
			String path;
			if(isFolder){
				path = content;
				set("doc_type","1");
			}else{
				if(OSName.getOSName().isWindows())
					path = folder + "\\" + content;
				else
					path = folder + "/" + content;
				set("doc_type","2");
			}
			set("document_to_sign",path);
			callJavaScript("onFileUpload",path);
		}

	}

	private void callJavaScript(final String func, final Object... args)
	{
		final JSObject window = JSObject.getWindow(AppletSignatura.this);
		if (window == null)
		{
			System.out.println("Could not get window from JSObject!!!");
			return;
		}
		System.out.println("Calling func through window");
		try
		{
			window.call(func, args);
		}
		catch (final Exception e)
		{
			System.out.println("Got error!!"+e.getMessage());
			e.printStackTrace();
			showError(e);
		}
		System.out.println("Finished JavaScript call...");
	}

	private void showError(final Exception e)
	{
		final String[] args = new String[]{e.getMessage()};
		final JSObject window = JSObject.getWindow(this);
		try
		{
			window.call("alert", args);
		}
		catch (final Exception ex)
		{
			System.out.println("Error showing error! "+ex);
		}
	}
}