package tmp;

import java.io.FileOutputStream;
import java.util.Arrays;


import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class MyTemp {

	/**
	 * @param args
	 */
	public static void main(String[] args) 
	{
		//TestB64Decoder();
		TestB64Encoder();
	}
	
	public static void TestB64Encoder()
	{
		String sample = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		sample = sample + "\n" + sample;
		try
		{
			String t1 = new BASE64Encoder().encode(sample.getBytes());
			//String t2 = javax.xml.bind.DatatypeConverter.printBase64Binary(sample.getBytes());
			String t2 = printBase64Binary(sample.getBytes());
			
			System.out.println(t1);
			System.out.println(t2);
			
			fileOut("t1.txt",t1.getBytes());
			fileOut("t2.txt",t2.getBytes());
			
			//System.out.println(Arrays.toString(t2.split("(?<=\\G.{76})")));
			
			System.out.println("==>" + t1.equals(t2));
			
		}
		catch(Exception exc)
		{
			System.out.println("Exc: " + exc.toString());
		}
	}
	
	public static String printBase64Binary(byte[] data)
	{
		String res = javax.xml.bind.DatatypeConverter.printBase64Binary(data);
		String arrData[] = res.split("(?<=\\G.{76})");
		res = "";
		int indexEnd = arrData.length-1;
		for(int i=0; i <= indexEnd; i++)
		{
			res += arrData[i];
			
			if (i != indexEnd)
			{
				res += "\r\n";
			}
		}
		return(res);
	}
	
	public static void fileOut(String name, byte[] data) throws Exception
	{
		FileOutputStream fout = new FileOutputStream(name);
		fout.write(data);
		fout.close();
	}
	
	public static void TestB64Decoder()
	{
		String sample = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		try
		{
			byte t1[] = new BASE64Decoder().decodeBuffer(sample);
			//byte t2[] = Base64.decode(sample);
			byte t3[] = javax.xml.bind.DatatypeConverter.parseBase64Binary(sample);
			//byte t4[] = lib.org.apache.xml.security.utils.Base64.decode(sample);
			//byte t5[] = Base64Utils.base64Decode(sample);
			if (t1.length != t3.length)
			{
				System.out.println("==> NO");
			}
			else
			{
				System.out.println("==>" + Arrays.equals(t1, t3));
			}
		}
		catch(Exception exc)
		{
			System.out.println("Exc: " + exc.toString());
		}
	}

}
