package org.catcert.utils;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cerca recursiva de directoris en funció d'un patró establert.
 * @author aalcaide
 *   
 */
public class FileListingUtils {

	private Pattern pattern;
	private List<File> files = new ArrayList<File>();	
	
	
	/**
	 * Constructor.
	 * @param pattern Patró de cerca de directoris
	 */
	public FileListingUtils(Pattern pattern){
		this.pattern = pattern;
	}
	
	/**
	 * Obté els fitxers, a partir d'un directori inicial especificat, que contenen al seu path el patró establert.
	 * @param startingDir directori d'inici de la cerca
	 * @return llista de fitxers trobats
	 * @throws FileNotFoundException
	 */
	public List<File> getFiles(File startingDir) throws FileNotFoundException {
		findFiles(startingDir);
		System.out.println("files.size(): "+files.size());
		return this.files;
		
	}
	
	/**
	 * Cerca recursiva de fitxers d'acord al patró establert, a partir d'un directori inicial especificat.
	 * Guarda els fitxers que responen al patró en una variable.
	 * @param startingDir directori d'inici de la cerca
	 * @returnllista de fitxers trobats
	 * @throws FileNotFoundException
	 */
	private List<File> findFiles(File startingDir) {
		List<File> result = new ArrayList<File>();
		try{
			validateDirectory(startingDir);
			File[] filesAndDirs = startingDir.listFiles();
			List<File> filesDirs = Arrays.asList(filesAndDirs);
			for (File file : filesDirs) {
				if (file.isDirectory() && file.length()>0) { 
					result.add(file);
					Matcher matcher = pattern.matcher(file.getAbsolutePath());
					if(matcher.find()) {
						this.files.add(file);
						System.out.println(file.getAbsolutePath());
					}
					List<File> deeperList = findFiles(file);
					if(deeperList!=null && deeperList.size()>0)
						result.addAll(deeperList);
				}
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		return result;
	}

	/**
	 * Un directori és vàlid si existeix, no és un fitxer, i es pot llegir.
	 */
	private void validateDirectory(File aDirectory) throws FileNotFoundException {
		if (aDirectory == null) {
			throw new IllegalArgumentException("Directory should not be null.");
		}
		if (!aDirectory.exists()) {
			throw new FileNotFoundException("Directory does not exist: "
					+ aDirectory);
		}
		if (!aDirectory.isDirectory()) {
			throw new IllegalArgumentException("Is not a directory: "
					+ aDirectory);
		}
		if (!aDirectory.canRead()) {
			throw new IllegalArgumentException("Directory cannot be read: "
					+ aDirectory);
		}
	}
	
}
