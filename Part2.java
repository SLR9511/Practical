package hw3;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.Base64;
import java.util.HashMap;
import org.apache.commons.io.IOUtils;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
//import sun.misc.BASE64Encoder;





public class Part2 {
	static final String SENDMESSAGE_PATH = "/sendMessage";
	static final String PROTOCOL_TYPE = "http";
   // static Key mOurKeys;
	KeyPair mDSAKeys = null;
	//MsgKeyPair mOurKeys;
	public String USER_AGENT = "Accept:  application/json";
	ArrayList<Message> mPendingMessages;
	public static final String PUBLIC_KEY_DSA="publicDSAKey";
	public static final String PRIVATE_KEY_DSA="privateDSAKey";
	public static final String PUBLIC_KEY_RSA = "publicRSAKey";
	public static final String PRIVATE_KEY_RSA = "privateRSAKey";
	
	public static String sendGet(String url) throws Exception {


		CloseableHttpClient client= HttpClients.createDefault();
		HttpGet request = new HttpGet(url);

		// add request header
		//request.addHeader("User-Agent", USER_AGENT);

		HttpResponse response = client.execute(request);

		System.out.println("\nSending 'GET' request to URL : " + url);
		System.out.println("Response Code : " +
                       response.getStatusLine().getStatusCode());

		BufferedReader rd = new BufferedReader(
                       new InputStreamReader(response.getEntity().getContent()));

		StringBuffer result = new StringBuffer();
		String line = "";
		while ((line = rd.readLine()) != null) {
			result.append(line);
		}
		return result.toString();
}
	public static String sendkey(String url, String key) throws Exception{
		URL u = new URL(url);
		boolean sendSucceed = true;
		try {
			java.net.HttpURLConnection  connection=null;
			OutputStreamWriter out=null;
			connection=(java.net.HttpURLConnection)u.openConnection();
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setDoOutput(true);
			connection.setDoInput(true);
			out= new OutputStreamWriter(connection.getOutputStream(), "UTF-8");
			String s1 = "{\"keyData\": \"" + key + "\"}";
			//System.out.println(s1);
			
			out.write(s1);
			//System.out.println(data);
			out.flush();
			out.close();
			System.out.println(connection.getResponseCode());
			//if(connection.getResponseCode()!=200)
				//throw new Exception();
			BufferedReader in = new BufferedReader(new InputStreamReader(  
					connection.getInputStream(), "UTF-8"));  
            String line;  
            // get the data from the server, the data must be a line which contains a JSON object
            while ((line = in.readLine()) != null) {  
                System.out.println(line);
                //in the i will got a message
            }  
            in.close();
		}
		catch (Exception e)
		{
			sendSucceed=false;
			e.printStackTrace();
		}
		return null;
	}
	
	public static String sendPostmsg(String url,String data,String reciver,int msgid) throws Exception {

		//String url = urll;//"http://localhost:5432/registerKey/yunchao";

		URL u = new URL(url);
		boolean sendSucceed=true;
		try {
			java.net.HttpURLConnection  connection=null;
			OutputStreamWriter out=null;
			connection=(java.net.HttpURLConnection)u.openConnection();
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setDoOutput(true);
			connection.setDoInput(true);
			out= new OutputStreamWriter(connection.getOutputStream(), "UTF-8");
			String s1 = "{\"recipient\":\"" + reciver + "\",\"messageID\":" + msgid + ",\"message\":\"" + data.replaceAll("\n", "") + "\"}";
			//System.out.println(s1);
			
			out.write(s1);
			//System.out.println(data);
			out.flush();
			out.close();
			System.out.println(connection.getResponseCode());
			//if(connection.getResponseCode()!=200)
				//throw new Exception();
			BufferedReader in = new BufferedReader(new InputStreamReader(  
					connection.getInputStream(), "UTF-8"));  
            String line;  
            // get the data from the server, the data must be a line which contains a JSON object
            while ((line = in.readLine()) != null) {  
                System.out.println(line);
                //in the i will got a message
            }  
            in.close();
		}
		catch (Exception e)
		{
			sendSucceed=false;
			e.printStackTrace();
		}
		return null;
		

	}

	
	public static byte[] getc2(String msg) throws JSONException, UnsupportedEncodingException{
		
		String c264 = msg;
		//System.out.println("old c2 is: "+c264);
		byte[] c2 = Base64.getDecoder().decode(msg);
        return c2;
	}
	
	public static String getsender(String msg){
		int index = msg.indexOf("senderID");
		int index2 = msg.indexOf("\",\"s");
		String senderID = msg.substring(index+11,index2);
		return senderID;
	}
	public static String getKey(String msg){
		int index = msg.indexOf("Data");
		//System.out.println(index);
		String key = msg.substring(index+8, msg.length()-2);
		return key;
	}
	public static String xor(byte[] s,String senderid) throws UnsupportedEncodingException{
		int length = senderid.length();
		byte[] sender = senderid.getBytes("UTF-8");
		byte[] newsender = "sssss".getBytes("UTF-8");
		for(int i = 0;i<length;i++)
		{
			sender[i] = (byte) (s[16+i]^sender[i]);
			s[16+i] = (byte) (sender[i]^newsender[i]); 
		}
		byte[] msg = "i".getBytes("UTF-8");
		s[16+length+1] = (byte) (s[16+length+1]^msg[0]);
		String result = Base64.getEncoder().encodeToString(s);
		System.out.println("new c2 is: "+result);
		return result;
	}
	public static Map<String,String> createDsaKeys() throws NoSuchAlgorithmException  
	{
		//BASE64Encoder encoder=new BASE64Encoder();
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");  
        keyPairGen.initialize(1024);    
        KeyPair keyPair = keyPairGen.generateKeyPair();    
        DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();  
        DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();  
        Map<String, String> keyMap = new HashMap<String, String>(2); 
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());//.replaceAll("\r|\n", "");//encoder.encode(publicKey.getEncoded()).replaceAll("\r|\n", "");
        String privateKeyBase64= Base64.getEncoder().encodeToString(privateKey.getEncoded());//.replaceAll("\r|\n", "");//encoder.encode(privateKey.getEncoded()).replaceAll("\r|\n", "");
        keyMap.put(PUBLIC_KEY_DSA, publicKeyBase64);  
        keyMap.put(PRIVATE_KEY_DSA, privateKeyBase64);  
        return keyMap;  
	}
	
	public static Map<String,String> createRsaKeys() throws NoSuchAlgorithmException  
	{
		//BASE64Encoder encoder=new BASE64Encoder();
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");  
        keyPairGen.initialize(1024);    
        KeyPair keyPair = keyPairGen.generateKeyPair();    
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();  
        Map<String, String> keyMap = new HashMap<String, String>(2); 
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());//.replaceAll("\r|\n", "");//encoder.encode(publicKey.getEncoded()).replaceAll("\r|\n", "");
        String privateKeyBase64= Base64.getEncoder().encodeToString(privateKey.getEncoded());//.replaceAll("\r|\n", "");//encoder.encode(privateKey.getEncoded()).replaceAll("\r|\n", "");
        keyMap.put(PUBLIC_KEY_RSA, publicKeyBase64);  
        keyMap.put(PRIVATE_KEY_RSA, privateKeyBase64);  
        return keyMap;  
	}
	
	public static String resign(String inputPrivateKey,String c1, String c2) throws Exception 
	{
		//byte[] dsaSignature;
		/*String concatenated = c1 + c2;
		
		//BASE64Decoder decoder=new BASE64Decoder();
		byte[] privateKeyByte= Base64.getDecoder().decode(inputPrivateKey);//decoder.decodeBuffer(inputPrivateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);  
        KeyFactory factory = KeyFactory.getInstance("DSA");  
        PrivateKey createdPrivateKey = factory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance("DSA");  
        signature.initSign(createdPrivateKey);  
        signature.update(concatenated.getBytes("UTF-8"));  
        return c1+" "+c2+" "+Base64.getEncoder().encodeToString(signature.sign()).replaceAll("\r|\n", "");
       // return encoder.encode(signature.sign()).replaceAll("\r|\n", "");*/
		//Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
    	//dsa.initSign(createdPrivateKey);
    	//dsa.update(concatenated.getBytes("UTF-8"));
    	//dsaSignature = dsa.sign();
		//BASE64Encoder encoder=new BASE64Encoder();
		//BASE64Decoder decoder = new BASE64Decoder();
		byte[] privateKeyByte= Base64.getDecoder().decode(inputPrivateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);  
        KeyFactory factory = KeyFactory.getInstance("DSA");  
        PrivateKey createdPrivateKey = factory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance("DSA");  
        signature.initSign(createdPrivateKey);  
        signature.update((c1+" "+ c2).getBytes("UTF-8"));  
        return c1+" "+c2+" "+Base64.getEncoder().encodeToString(signature.sign()).replaceAll("\r|\n", "");
    	
	}
	
	public static String re(String c1, String c2, String DSAKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException, Exception{
		String concatenated = c1+" "+c2;
		//KeyPairGenerator keyGenDSA = KeyPairGenerator.getInstance("DSA");
        //keyGenDSA.initialize(1024);
        //PrivateKey DSA;
        //DSA = keyGenDSA.generateKeyPair().getPrivate();
		byte[] privateKeyByte = Base64.getDecoder().decode(DSAKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);  
        KeyFactory factory = KeyFactory.getInstance("DSA");  
        PrivateKey createdPrivateKey = factory.generatePrivate(keySpec);
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
    	dsa.initSign(createdPrivateKey);
    	dsa.update(concatenated.getBytes("UTF-8"));
    	byte[] dsaSignature = dsa.sign();	
    	String dsaBase64 = Base64.getEncoder().encodeToString(dsaSignature);
    	return c1+" "+c2+" "+dsaBase64;
    	
	}
	
	public String decryptMessage(String ciphertext, String senderId, MsgKeyPair senderKey) throws BadPaddingException {
		byte[] aesKey;
		byte[] aesPlaintext;
		KeyPairGenerator keyGenRSA;
		PrivateKey RSA = null;
		try {
			keyGenRSA = KeyPairGenerator.getInstance("RSA");
			keyGenRSA.initialize(1024);

	        RSA = keyGenRSA.generateKeyPair().getPrivate();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
		// Make sure sure that the sender's key is valid, and so is ours
		/*if (senderKey.isValidForSending() == false || mOurKeys == null)  {
			System.out.println("Error: invalid keys");
			return null;
		}*/

		// First, parse the input ciphertext into three substrings
		// (RSA Ciphertext, AES ciphertext, Signature)
		String[] parsedString = ciphertext.trim().split(" ");
		if (parsedString.length != 3) {
			System.out.println("1");
			return null;
		}

		// Decode the signature and verify it against the first
		// two encoded strings
	   try {
	    	// Initialize DSA verifier (with SHA1)
			byte[] decodedSignature = Base64.getDecoder().decode(parsedString[2]);
	    	Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
	    	//System.out.println(senderKey.getDSAPublicKey());
	    	sig.initVerify(senderKey.getDSAPublicKey());
	    	
	    	// Concatenate RSA ciphertext + delimiter + AES ciphertext
	    	// Feed raw bytes into signature verifier
		    String concatenated = parsedString[0] + " " + parsedString[1];
	    	sig.update(concatenated.getBytes("UTF-8"));
	    	System.out.println(sig.verify(decodedSignature));
	    	// Verify the signature
	    	if (sig.verify(decodedSignature) == false) {
	    		System.out.println("2");
	    		// Verification failed.
	    		return null;
	    	}
	    } catch (Exception e) {
	    	System.out.println("3");
	    	return null;
	    }
	    
		// Instantiate an RSA cipher to decrypt the first component
	    // Now encrypt the AES key using the sender's RSA key
	    Cipher rsaCipher;
	    try {
	    	rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    	System.out.println("1111");
		    rsaCipher.init(Cipher.DECRYPT_MODE, RSA);
		    System.out.println("2222");
			byte[] decodedRSACiphertext = Base64.getDecoder().decode(parsedString[0]);
			System.out.println("3333");
			//System.out.println(parsedString[0]);
			for(int i=0;i<decodedRSACiphertext.length;i++)
				System.err.print(decodedRSACiphertext[i]);
			System.out.print('\n');
			System.out.println(decodedRSACiphertext.length);
		    aesKey = rsaCipher.doFinal(decodedRSACiphertext);
		    System.out.println("4444");
		    
		    // Check that decryption produced a 16-byte key
		    if (aesKey.length != 16) {
		    	System.out.println("4");
		    	return null;
		    }
	    } catch (Exception e) {
	    	e.printStackTrace();
	    	System.out.println("5");
			return null; 
		}

	    // Use the resulting AES key to instantiate an AES cipher
	    // and decrypt the payload
	    Cipher aesCipher;
	    try {
	    	// Decode AES ciphertext
			byte[] decodedAESCiphertext = Base64.getDecoder().decode(parsedString[1]);
			
	    	// Initialize AES with the key
	    	SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
	        byte[] iv = Arrays.copyOfRange(decodedAESCiphertext, 0, 16);
	        byte[] actualCiphertext = Arrays.copyOfRange(decodedAESCiphertext, 16, decodedAESCiphertext.length);
	        IvParameterSpec ivspec = new IvParameterSpec(iv);
	    	aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
	    	aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivspec);
	    	
	        // AES decrypt the ciphertext buffer
	        aesPlaintext = aesCipher.doFinal(actualCiphertext);   
	        
	        // Remove the PKCS7 padding
	        if (aesPlaintext.length >= 16) {
	        	int paddingLen = aesPlaintext[aesPlaintext.length - 1];
	        	if (paddingLen < 0 || paddingLen > 16) {
	        		System.out.println("6");
	        		return null;
	        	}
	        	
	        	for (int i = 0; i < paddingLen; i++) {
	        		if (aesPlaintext[(aesPlaintext.length - 1) - i] != paddingLen) {
	        			// Bad padding
	        			System.out.println("7");
	        			return null;
	        		}
	        	}
	        	
	        	// Padding checks out -- remove it
	        	aesPlaintext = Arrays.copyOfRange(aesPlaintext, 0, (aesPlaintext.length) - paddingLen);
	        } else {
	        	// Error: plaintext too small
	        	System.out.println("8");
	        	return null;
	        }
	    } catch (Exception e) {
	    	System.out.println("9");
			return null; 
		}
	    CRC32 crc = new CRC32();
    	crc.update(aesPlaintext, 0, aesPlaintext.length - 4);
    	long crcVal = crc.getValue();
    	byte[] crcBytes = {0, 0, 0, 0, 0, 0, 0, 0};
    	System.arraycopy(aesPlaintext, aesPlaintext.length - 4, crcBytes, 4, 4);
    	if (crcVal != bytesToLong(crcBytes)) {
    		// Invalid CRC
    		System.out.println("10");
    		return null;
    	}
    	
    	// Strip off the CRC and recover the plaintext to a string
    	String messagePlaintext = new String(Arrays.copyOfRange(aesPlaintext, 0, aesPlaintext.length - 4));
    	
    	// Break the decrypted string into <senderID>:<message>, and check
    	// that <senderID> matches the expected sender
    	int delimiterLoc = messagePlaintext.indexOf(":");
    	if (delimiterLoc < 1) {
    		System.out.println("11");
    		return null;
    	}
    	if (messagePlaintext.substring(0, delimiterLoc).equals(senderId) == false) {
    		System.out.println("12");
    		return null;
    	}
    	
    	// Finally, trim off the sender ID portion and return the 
    	// message itself
    	return messagePlaintext.substring(delimiterLoc + 1);
	}
	
	public long bytesToLong(byte[] bytes) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.put(bytes);
	    buffer.flip(); // needed to handle byte order issues 
	    return buffer.getLong();
	}
	
	public static boolean dsaValidate(String plain,String inputPublicKey,String dsaSign) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException
	{
		//BASE64Encoder encoder=new BASE64Encoder();
		//BASE64Decoder decoder=new BASE64Decoder();
		byte[] publicKeyByte=Base64.getDecoder().decode(inputPublicKey);//decoder.decodeBuffer(inputPublicKey);
		byte[] dsaSignByte=Base64.getDecoder().decode(dsaSign);//decoder.decodeBuffer(dsaSign);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyByte);  
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");    
        PublicKey createPublicKey = keyFactory.generatePublic(keySpec);  
          
        Signature signature = Signature.getInstance("DSA");     
        signature.initVerify(createPublicKey);   
        signature.update(plain.getBytes("UTF-8"));  
          
        return signature.verify(dsaSignByte);
	}


}

