package org.catcert.net;


import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;

import org.catcert.crypto.utils.Utils;

//import sun.misc.BASE64Encoder;


/**
 * 
 * @author oburgos
 *
 */
public class HTTPSender {

	private HashMap<String, String> proxySettings;
	private int ContentLength;


	/**
	 * 
	 * @param proxySettings
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyManagementException 
	 */
	public HTTPSender(HashMap<String, String> proxy) {
		proxySettings = proxy;
	}

	/**
	 * 
	 * @param url
	 * @throws MalformedURLException
	 * @throws IOException
	 */
	private void detectProxy(URL url)
	{
		try {

			ProxySelector selector = ProxySelector.getDefault();				
			List list = selector.select(url.toURI());
			System.out.println("S'ha trobat " + list.size() + " proxy/ies en la configuració de sortida a Internet");
			for (int i = 0; i<list.size(); i++)
				System.out.println("Proxy " + i + ":" + ((Proxy)list.get(i)).toString());

			Proxy proxy = (Proxy) list.get(0);
			if(proxy.address() != null) { //Hi ha proxy configurat per accedir a la URL
				StringTokenizer token = new StringTokenizer(proxy.address().toString(), ":");
				String proxy_server = token.nextToken();
				if(proxy_server.startsWith("/"))
					proxy_server = proxy_server.substring(1);
				String proxy_port = token.nextToken();
				if (proxy_server != null && proxy_port != null) {
					System.out.println("Utilitzant proxy: " + proxy_server + ":" + proxy_port);
					String dest = url.getFile();
					url = new URL("http", proxy_server, new Integer(proxy_port), dest);
					System.out.println("url canviada per usar proxy: " + url.toString());
				}
				else
					System.out.println("Problemes recuperant els paràmetres del proxy per defecte.");
			}
			else
				System.out.println("No cal configurar proxy");

			/*ProxyInfo info[] = ProxyService.getProxyInfo(url);

			if(info != null && info.length>0)
			{
				try {
					String serverName = info[0].getHost();
					int serverPort = info[0].getPort();

					proxySettings = new HashMap<String, String>();			
					proxySettings.put("serverName", serverName);
					proxySettings.put("serverPort", new Integer(serverPort).toString());
					System.out.println("PROXY = " + proxySettings.get("serverName") + ":" + proxySettings.get("serverPort"));
					String dest = url.getFile();
					url = new URL("http", info[0].getHost(), info[0].getPort(), dest);
				} catch (NullPointerException e) {
					System.out.println("DIRECT PROXY");
				}
			}
			else
				System.out.println("DIRECT PROXY");*/

		} catch (IOException e) {
			System.out.println("DIRECT PROXY");		
		} catch (URISyntaxException e) {
			System.out.println("DIRECT PROXY");
		}

		// cookie de la sessió establerta pel navegador
		//(String)JSObject.getWindow(AppletSignatura.this).eval("document.cookie");		
	}

	/**
	 * 
	 * @param url
	 * @param timestampreq
	 * @return
	 * @throws HTTPSenderException
	 */
	public InputStream postTSQ(URL url, byte[] timestampreq) throws HTTPSenderException {
		return postMethod(url, timestampreq, "application/timestamp-query");
	}

	/**
	 * 
	 * @param url
	 * @param timestampreq
	 * @return
	 * @throws HTTPSenderException
	 */
	public InputStream postXML(URL url, byte[] timestampreq) throws HTTPSenderException {
		return postMethod(url, timestampreq, "application/xml");
	}
	
	public InputStream postOCSPQ(URL url, byte[] ocspreq) throws HTTPSenderException {
		return postMethod(url, ocspreq, "application/ocsp-request");
	}

	/**
	 * 
	 * @param url
	 * @param request
	 * @param mimeType
	 * @return
	 * @throws HTTPSenderException
	 */
	public InputStream postMethod(URL url, byte[] request, String mimeType) throws HTTPSenderException {
		try {
			
			HttpURLConnection con = null;
			
			if (proxySettings == null){
				detectProxy(url);
				con = (HttpURLConnection) url.openConnection();
			}
			else {
				String proxy_server = proxySettings.get("serverName");
				String proxy_port = proxySettings.get("serverPort");
				InetSocketAddress sockAddr = new InetSocketAddress(InetAddress.getByName(proxy_server), new Integer(proxy_port).intValue());
				Proxy proxy = new Proxy(Proxy.Type.HTTP, sockAddr);
				con = (HttpURLConnection) url.openConnection(proxy);
				System.out.println("Utilitzant proxy: " + proxy_server + ":" + proxy_port);
			}

			// Set the Proxy-Authorization header for basic proxy authorization
			// If you dont do this you will get 'Unable to tunnel through proxy.
			// Proxy returns "HTTP/1.0 407 Authenticate required' IOException
			// You also will need a base64 encoder to encode the userid and password string
			if (proxySettings != null) { // cal utilitzar proxy
				if(proxySettings.containsKey("Cookie")) // si existeix cookie de sessió...
					con.setRequestProperty("Set-Cookie", proxySettings.get("Cookie"));
				else if (proxySettings.containsKey("username")) // sino afegim la property amb username i password
					//con.setRequestProperty("Proxy-Authorization", "Basic " + new BASE64Encoder().encode((proxySettings.get("username") + ":" + proxySettings.get("password")).getBytes()));
					con.setRequestProperty("Proxy-Authorization", "Basic " + Utils.printBase64Binary((proxySettings.get("username") + ":" + proxySettings.get("password")).getBytes()));
				
			}

			// Set the content type to be sent & type of request
			con.setRequestProperty("Content-Type", mimeType);
			con.setRequestMethod("POST");
			con.setDoInput(true);
			con.setDoOutput(true);
			
			// Send data
			DataOutputStream out = new DataOutputStream(con.getOutputStream());
			out.write(request);
			out.flush();
			out.close();

			// Get response & HTTP code
			int responseCode = con.getResponseCode();
			if (con.getResponseCode() == HttpURLConnection.HTTP_OK) {
				storeCookie(con);
				ContentLength = con.getContentLength();
				return con.getInputStream();
			}
			else if (responseCode >= 300 && responseCode <= 307 && responseCode != 306 && responseCode != HttpURLConnection.HTTP_NOT_MODIFIED) {
				URL base = con.getURL();
				String loc = con.getHeaderField("Location");
				URL target = null;
				if (loc != null)
					target = new URL(base, loc);
				con.disconnect();
				// Redirection should be allowed only for HTTP and HTTPS
				// and should be limited to 5 redirections at most.
				if (target == null || !(target.getProtocol().equals("http") || target.getProtocol().equals("https")))
					throw new SecurityException("illegal URL redirect");	            
				con = (HttpURLConnection)target.openConnection();
				if (con.getResponseCode() != HttpURLConnection.HTTP_OK)
					throw new HTTPSenderException("HTTP Error Code: " + con.getResponseCode());
				storeCookie(con);
				ContentLength = con.getContentLength();
				return con.getInputStream();
			}
			else
				throw new HTTPSenderException("HTTP Error Code: " + con.getResponseCode());

		} catch (MalformedURLException e) {
			e.printStackTrace();
			throw new HTTPSenderException(e);
		} catch (IOException e) {
			e.printStackTrace();
			throw new HTTPSenderException(e);
		}
	}

	/**
	 * 
	 * @return
	 */
	public int returnCurrentContentLength() {
		return ContentLength;
	}

	/**
	 * 
	 * @param url
	 * @return
	 * @throws HTTPSenderException
	 */
	public InputStream getMethod(URL url) throws HTTPSenderException {

		try {
			if (proxySettings == null)
				detectProxy(url);
			else {
				String dest = url.getFile();
				url = new URL("http", proxySettings.get("serverName"), new Integer(proxySettings.get("serverPort")).intValue(), dest);
				System.out.println("url canviada per usar proxy: " + url.getFile());
			}

			HttpURLConnection con = (HttpURLConnection) url.openConnection();

			// Set the Proxy-Authorization header for basic proxy authorization
			// If you don't do this you will get 'Unable to tunnel through proxy.
			// Proxy returns "HTTP/1.0 407 Authenticate required' IOException
			// You also will need a base64 encoder to encode the userid and password string
			if (proxySettings != null) { // cal utilitzar proxy
				if(proxySettings.containsKey("Cookie")) // si existeix cookie de sessió...
					con.setRequestProperty("Set-Cookie", proxySettings.get("Cookie"));
				else if (proxySettings.containsKey("username")) // sino afegim la property amb username i password
					//con.setRequestProperty("Proxy-Authorization", "Basic " + new BASE64Encoder().encode((proxySettings.get("username") + ":" + proxySettings.get("password")).getBytes()));
					con.setRequestProperty("Proxy-Authorization", "Basic " + Utils.printBase64Binary((proxySettings.get("username") + ":" + proxySettings.get("password")).getBytes()));
			}

			// Set the content type to be sent & type of request
			con.setRequestMethod("GET");
			con.setDoInput(true);
			con.setDoOutput(false);

			// Get response & HTTP code
			int responseCode = con.getResponseCode();
			if (con.getResponseCode() == HttpURLConnection.HTTP_OK) {
				storeCookie(con);
				ContentLength = con.getContentLength();
				return con.getInputStream();
			}				
			else if (responseCode >= 300 && responseCode <= 307 && responseCode != 306 && responseCode != HttpURLConnection.HTTP_NOT_MODIFIED) {
				URL base = con.getURL();
				String loc = con.getHeaderField("Location");
				URL target = null;
				if (loc != null)
					target = new URL(base, loc);
				con.disconnect();
				// Redirection should be allowed only for HTTP and HTTPS
				if (target == null || !(target.getProtocol().equals("http") || target.getProtocol().equals("https")))
					throw new SecurityException("illegal URL redirect");	            
				con = (HttpURLConnection)target.openConnection();
				if (con.getResponseCode() != HttpURLConnection.HTTP_OK)
					throw new HTTPSenderException("HTTP Error Code: " + con.getResponseCode());
				storeCookie(con);
				ContentLength = con.getContentLength();
				return con.getInputStream();
			}
			else
				throw new HTTPSenderException("HTTP Error Code: " + con.getResponseCode());

		} catch (MalformedURLException e) {
			e.printStackTrace();
			throw new HTTPSenderException(e);
		} catch (IOException e) {
			e.printStackTrace();
			throw new HTTPSenderException(e);
		}
	}

	/**
	 * 
	 * @param con
	 */
	private void storeCookie(HttpURLConnection con) {
		// read the cookie string if you want to store it (especially useful to capture the
		// session id if returned from the server you can then add this to future requests
		String cookie = con.getHeaderField("Set-Cookie");
		if(cookie != null) {
			int index = cookie.indexOf(";");
			if(index >= 0) cookie = cookie.substring(0, index);
			if (!cookie.equals("")) {
				if(proxySettings!=null) {
					if (proxySettings.containsKey("Cookie"))
						System.out.println("Old Cookie: " + proxySettings.get("Cookie"));
				}
				else proxySettings = new HashMap<String, String>();
				proxySettings.put("Cookie", cookie);
			}					
			System.out.println("New Cookie: " + proxySettings.get("Cookie"));
		}
	}
}