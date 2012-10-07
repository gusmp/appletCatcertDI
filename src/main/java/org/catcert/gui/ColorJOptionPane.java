package org.catcert.gui;

import java.awt.Color;
import java.awt.Component;
import java.awt.HeadlessException;
import java.net.URL;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.UIManager;

@SuppressWarnings("serial")
public class ColorJOptionPane extends JOptionPane {

	public JDialog preparedDialog;
	public JOptionPane preparedPane;

	public ColorJOptionPane(){
	}

	/**
	 * 
	 * @param c
	 */
	public ColorJOptionPane(Color c){
		UIManager.put("OptionPane.background",c);
		UIManager.put("Panel.background",c);
		//UIManager.put("Button.background",c);
	}

	/**
	 * 
	 * @param parentComponent
	 * @param message
	 * @param title
	 * @param optionType
	 * @param messageType
	 * @param icon
	 * @param options
	 * @param initialValue
	 * @return
	 * @throws HeadlessException
	 */
	public int showCATCertDialog(Component parentComponent, Object message, String title, int optionType, int messageType,
			Icon icon, Object[] options, Object initialValue) throws HeadlessException {

		JOptionPane pane = new JOptionPane(message, messageType, optionType, icon, options, initialValue);
		pane.setInitialValue(initialValue);
		pane.setComponentOrientation(((parentComponent == null) ? getRootFrame() : parentComponent).getComponentOrientation());

		URL url = CertSelectionDialog.class.getResource("/org/catcert/gui/einaCATCert.png");
		ImageIcon einaLogo = new ImageIcon(url);
		JLabel einaLabel = new JLabel(einaLogo);

		pane.add(new JLabel("<html><br><br></html>"));
		pane.add(einaLabel);

		JDialog dialog = pane.createDialog(parentComponent, title);

		pane.selectInitialValue();
		dialog.setFocusable(true);
		dialog.setAlwaysOnTop(true);
		dialog.setVisible(true);
		dialog.dispose();

		Object selectedValue = pane.getValue();

		if(selectedValue == null)
			return CLOSED_OPTION;
		if(options == null) {
			if(selectedValue instanceof Integer)
				return ((Integer)selectedValue).intValue();
			return CLOSED_OPTION;
		}
		for(int counter = 0, maxCounter = options.length; counter < maxCounter; counter++) {
			if(options[counter].equals(selectedValue))
				return counter;
		}
		return CLOSED_OPTION;
	}

	/**
	 * 
	 * @param parentComponent
	 * @param message
	 * @param title
	 * @param optionType
	 * @param messageType
	 * @param icon
	 * @param options
	 * @param initialValue
	 * @throws HeadlessException
	 */
	public void prepareProgressDialog(Component parentComponent, Object message, String title, int optionType, int messageType,
			Icon icon, Object[] options, Object initialValue) throws HeadlessException {

		preparedPane = new JOptionPane(message, messageType, optionType, icon, options, initialValue);
		preparedPane.setInitialValue(initialValue);
		preparedPane.setComponentOrientation(((parentComponent == null) ? getRootFrame() : parentComponent).getComponentOrientation());

		URL url = CertSelectionDialog.class.getResource("/org/catcert/gui/einaCATCert.png");
		ImageIcon einaLogo = new ImageIcon(url);
		JLabel einaLabel = new JLabel(einaLogo);

		preparedPane.add(new JLabel("<html><br><br></html>"));
		preparedPane.add(einaLabel);

		preparedDialog = preparedPane.createDialog(parentComponent, title);

		preparedPane.selectInitialValue();
	}

	/**
	 * 
	 * @return
	 */
	public int showProgressDialog() {
		preparedDialog.setVisible(true);
		preparedDialog.dispose();

		Object selectedValue = preparedPane.getValue();

		if(selectedValue == null)
			return CLOSED_OPTION;
		if(options == null) {
			if(selectedValue instanceof Integer)
				return ((Integer)selectedValue).intValue();
			return CLOSED_OPTION;
		}
		for(int counter = 0, maxCounter = options.length; counter < maxCounter; counter++) {
			if(options[counter].equals(selectedValue))
				return counter;
		}
		return CLOSED_OPTION;
	}
}