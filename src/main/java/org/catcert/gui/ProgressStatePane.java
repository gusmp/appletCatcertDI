package org.catcert.gui;

import java.awt.Color;

import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;

import org.catcert.thread.SwingWorker;

public class ProgressStatePane extends JPanel {

	/**
	 * 
	 */
	private static final long serialVersionUID = 628779174483495294L;
		
	private JProgressBar progressBar;
	private JLabel statusField;
	private SwingWorker worker;
	
	private static final int totalCicles = 4;
	private int currentProgress;

//	private AppletSignatura source;
//	private String[] multiSignature;
//	private Vector<byte[]> ftbsigned;
//	private Vector<String> ftbsignedName; 
//	private CertificateStore store;
//	private String alias;
//	private char[] PIN;
//	private String algorithm;
//	private String policy_algorithm;

	private boolean done;

	
	public ProgressStatePane(Color bg){
		progressBar = new JProgressBar(0, totalCicles);
		currentProgress = 0;
		progressBar.setValue(currentProgress);
		progressBar.setStringPainted(true);

		statusField = new JLabel("Signing", JLabel.LEFT);
		statusField.setAlignmentX(CENTER_ALIGNMENT);

		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		setBackground(bg);

		add(progressBar);
		add(statusField);
	}
	
	
	
//	public ProgressStatePane(Color bg, AppletSignatura source,
//			String[] multiSignature, Vector<byte[]> ftbsigned, Vector<String> ftbsignedName, 
//			CertificateStore store, String alias, char[] PIN, String algorithm, String policy_algorithm, boolean psisValidation) throws HTTPSenderException 
//	{
//		this.source          = source;          
//		this.multiSignature  = multiSignature;    
//		this.ftbsigned       = ftbsigned;       
//		this.ftbsignedName   = ftbsignedName;   
//		this.store           = store;           
//		this.alias           = alias;               
//		this.PIN             = PIN;                 
//		this.algorithm       = algorithm;           
//		this.policy_algorithm= policy_algorithm;
//		
//		progressBar = new JProgressBar(0, totalCicles);
//		currentProgress = 0;
//		progressBar.setValue(currentProgress);
//		progressBar.setStringPainted(true);
//
//		statusField = new JLabel("Signing", JLabel.LEFT);
//		statusField.setAlignmentX(CENTER_ALIGNMENT);
//
//		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
//		setBackground(bg);
//
//		add(progressBar);
//		add(statusField);
//	}
	/**
	 * 
	 * @param i
	 */
	public void updateStatus(final int i, final String msg) {
//		progressBar.setValue(i);
//		statusField.setText(msg);
		
		Runnable doSetStateValue = new Runnable() {
			public void run() {
				progressBar.setValue(i);
				statusField.setText(msg);
			}
		};
		SwingUtilities.invokeLater(doSetStateValue);
	}

	/**
	 *
	 *
	 */
	public void startProgress(){
		/* Invoking start() on the SwingWorker causes a new Thread
		 * to be created that will call construct(), and then
		 * finished().
		 */
		worker = new SwingWorker() {
			public Object construct() {
				return doWork();
			}
			public void finished() {
				done = true;
				JOptionPane state;
				
				try {
					state = ((JOptionPane)ProgressStatePane.this.getParent().getParent().getParent().getParent());
				} catch (ClassCastException e) {
					state =  ((JOptionPane)ProgressStatePane.this.getParent().getParent());
				}
				state.setValue(ProgressStatePane.this);
			}
		};
		worker.start();
	}

	/**
	 * 
	 * @return
	 */
	public Object doWork() {
		//TODO
		//boolean result = source.runSignature(this, multiSignature, ftbsigned, ftbsignedName, store, alias, PIN, algorithm, policy_algorithm);
		//System.out.println("result: "+result);
		//return result;
		return true;	
	}
	
	public boolean isDone() {
		return done;
	}
	
	public int close(){
		return JOptionPane.CLOSED_OPTION;
	}

	
}
