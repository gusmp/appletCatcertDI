package org.catcert.gui;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;

import org.catcert.net.HTTPSenderException;
import org.catcert.thread.SwingWorker;

/**
 * 
 * @author oburgos
 *
 */
public class DownloadProgressBar extends JPanel {

	private static final long serialVersionUID = -8896676299569321852L;
	private InputStream file;
	private int totalCicles;
	private int currentProgress;
	private JProgressBar progressBar;
	private SwingWorker worker;
	private JLabel statusField;
	private ByteArrayOutputStream byteArray;
	private boolean done;

	/**
	 * 
	 * @param urlFile
	 * @param fileNumber
	 * @param totalFiles
	 * @param totalBytes
	 * @throws HTTPSenderException 
	 */
	public DownloadProgressBar(InputStream urlFile, int fileNumber, int totalFiles, int totalBytes, Color bg) throws HTTPSenderException {
		file = urlFile;
		totalCicles = totalBytes/1024;
		progressBar = new JProgressBar(0, totalCicles);
		currentProgress = 0;
		progressBar.setValue(currentProgress);
		progressBar.setStringPainted(true);
		statusField = new JLabel("Descarregant document " + fileNumber + " de " + totalFiles, JLabel.LEFT);
		statusField.setAlignmentX(CENTER_ALIGNMENT);

		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		setBackground(bg);

		add(progressBar);
		add(statusField);
	}

	/**
	 * 
	 * @return
	 */
	public byte[] getDownloadedFile() {
		return byteArray.toByteArray();
	}

	/**
	 * 
	 * @param i
	 */
	public void updateStatus(final int i) {
		Runnable doSetProgressBarValue = new Runnable() {
			public void run() {
				progressBar.setValue(i);
			}
		};
		SwingUtilities.invokeLater(doSetProgressBarValue);
	}

	/**
	 *
	 *
	 */
	public void startDownload(){
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
				
				JOptionPane progress;
				
				try {
					progress = ((JOptionPane)DownloadProgressBar.this.getParent().getParent().getParent().getParent());
				} catch (ClassCastException e) {
					progress =  ((JOptionPane)DownloadProgressBar.this.getParent().getParent());
				}
				progress.setValue(DownloadProgressBar.this);
			}
		};
		worker.start();
	}

	/**
	 * 
	 * @return
	 */
	public Object doWork() {
		byteArray = new ByteArrayOutputStream();
		try {
			byte buffer[] = new byte[1024];
			int c = 0;

			while ((c = file.read(buffer)) > 0) {
				currentProgress ++;
				updateStatus(currentProgress);
				byteArray.write(buffer, 0, c);
			}
			byteArray.flush();
			file.close();
			currentProgress = totalCicles;
			updateStatus(currentProgress);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return "Done";
	}
	
	public boolean isDone() {
		return done;
	}
}