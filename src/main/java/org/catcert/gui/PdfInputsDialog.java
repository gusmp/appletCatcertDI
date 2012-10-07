package org.catcert.gui;

import java.awt.Color;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

//import sun.misc.BASE64Decoder;


/**
 * 
 * @author oburgos
 *
 */
public class PdfInputsDialog {

	private Object[] Result = new Object[8];

	//	[0] -> 0, no crear res; 1, visible; 2, invisible.
	//	[1] -> signature_field
	//  [2] -> certification level (0, no certificar; 1, no permetre canvis; 2, permetre omplir form; 3, omplir form i anotacions)
	//	[3] -> true, timestamped; false, normal.
	//	[4] -> reason
	//	[5] -> location
	//  [6] -> signature image
	//	[7] -> coordenades signatura visible

	private boolean pdf_visible_signature;
	private String pdf_signature_field;
	private int pdf_certification_level;
	private boolean pdf_timestamp;
	private String pdf_reason;
	private String pdf_location;
	private String pdf_signature_image;
	private HashMap<String, Integer> signature_coordinates;
	private Color color;
	private ImageIcon logo;
	private ResourceBundle txt;

	/**
	 * @param visible
	 * @param field
	 * @param certLevel
	 * @param TS
	 * @param reason
	 * @param location
	 * @param b64sigImage
	 * @param coordinates
	 * @param appletColor
	 * @param appletLogo
	 * @param txt
	 * @throws IOException
	 */
	public PdfInputsDialog(boolean visible, String field, int certLevel, boolean TS, String reason, String location, String b64sigImage, HashMap<String, Integer> coordinates, Color appletColor, String appletLogo, ResourceBundle txt) throws IOException {
		pdf_visible_signature = visible;
		pdf_signature_field = field;
		pdf_certification_level = certLevel;
		pdf_timestamp = TS;
		pdf_reason = reason;
		pdf_location = location;
		pdf_signature_image = b64sigImage;
		signature_coordinates = coordinates;
		color = appletColor;
		if (appletLogo != null)
			//logo = new ImageIcon(new BASE64Decoder().decodeBuffer(appletLogo));
			logo = new ImageIcon(javax.xml.bind.DatatypeConverter.parseBase64Binary(appletLogo));
		else {
			URL url = CertSelectionDialog.class.getResource("/org/catcert/gui/logo.png");
			logo = new ImageIcon(url);
		}
		this.txt = txt;
	}

	/**
	 * Construeix el panell de diàleg de signatura de PDF. Mostra la selecció del camp de signatura, motiu i lloc en funció dels paràmetres ja definits
	 * i dels camps de signatura buits que es passen com a paràmetre.
	 * 
	 * @param names Llistat dels camps de signatura disponibles per al diàleg de selecció.
	 * @return true si s'accepta, false si es cancel·la el procés.
	 */
	private boolean showDataInput(ArrayList names) {		
		ComboBox signatureFields = null;
		JTextField reason = new JTextField();
		JTextField location = new JTextField();

		ImageIcon customLogo = logo;		
		JLabel logoLabel = new JLabel(customLogo);
		JLabel space = new JLabel(txt.getString("label"));

		Object[] message = null;

		if(!names.isEmpty() && pdf_signature_field == null) { // si hi ha camps buits i no hi ha el camp preseleccionat (control de preselecció posterior)...
			names.add("Nou camp de signatura");
			signatureFields = new ComboBox(names.toArray());
			signatureFields.setPrototypeDisplayValue("123456789012345678901234");
			if(pdf_reason == null) {
				message = new Object[] {logoLabel, space, txt.getString("selectSignatureField1"), signatureFields, txt.getString("selectReason1"), reason};
				if(pdf_location == null)
					message = new Object[] {logoLabel, space, txt.getString("selectSignatureField2"), signatureFields, txt.getString("selectReason3"), reason, txt.getString("selectLocation1"), location};
			}
			else {
				message = new Object[] {logoLabel, space, txt.getString("selectSignatureField2"), signatureFields};
				if(pdf_location == null)
					message = new Object[] {logoLabel, space, txt.getString("selectSignatureField2"), signatureFields, txt.getString("selectLocation1"), location};				
			}
		}
		else {
			if(pdf_reason == null) {
				message = new Object[] {logoLabel, space, txt.getString("selectReason2"), reason};
				if(pdf_location == null)
					message = new Object[] {logoLabel, space, txt.getString("selectReason2"), reason, txt.getString("selectLocation1"), location};
			}
			else {
				if(pdf_location == null)
					message = new Object[] {logoLabel, space, txt.getString("selectLocation2"), location};
			}
		}

		if (message != null) {
			Object[] options = {txt.getString("okButton"), txt.getString("cancelButton")};
			if(new ColorJOptionPane(color).showCATCertDialog(null, message, "", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]) == JOptionPane.OK_OPTION) {
				// Obtenim valors
				if(signatureFields != null) {
					pdf_signature_field = (String)signatureFields.getSelectedItem();
					if(pdf_signature_field.equals("Nou camp de signatura"))
						names.clear();
				}
				if(pdf_reason == null)
					pdf_reason = reason.getText();
				if(pdf_location == null)
					pdf_location = location.getText();
			}
			else
				return false;				
		}
		// No hi ha havia diàleg o s'han completat els valors
		return true;
	}

	/**
	 * Es crida des de la classe de generació de signatura en PDFs i defineix com ha de ser la signatura.
	 * 
	 * @param names
	 * @param alreadycertified
	 * @return
	 */
	public Object[] run(ArrayList names, boolean alreadycertified) {
		if(showDataInput(names)) {
			if(pdf_visible_signature)
				Result[0] = 1;
			else
				Result[0] = 2;
			Result[1] = pdf_signature_field;
			if(alreadycertified) // ja existeix alguna signatura
				Result[2] = 0;
			else
				Result[2] = pdf_certification_level;
			Result[3] = pdf_timestamp;
			Result[4] = pdf_reason;
			Result[5] = pdf_location;
			Result[6] = pdf_signature_image;			
			Result[7] = signature_coordinates;
			
			//	[0] -> 0, no crear res; 1, visible; 2, invisible.
			//	[1] -> signature_field
			//	[2] -> coordenades signatura visible
			//  [3] -> certification level (0, no certificar; 1, no permetre canvis; 2, permetre omplir form; 3, omplir form i anotacions)
			//	[4] -> true, timestamped; false, normal.
			//	[5] -> reason
			//	[6] -> location
			//  [7] -> signature image
		}
		else
			Result[0] = 0;

		return Result;
	}
}