package hw3;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONException;
import org.json.JSONObject;

public class Part3 {
	static final String READRECEIPT_MESSAGE = ">>>READMESSAGE";
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
public static byte[] getc2(String msg) throws JSONException, UnsupportedEncodingException{
		
		String c264 = msg;
		//System.out.println("old c2 is: "+c264);
		byte[] c2 = Base64.getDecoder().decode(msg);
        return c2;
	}

public static int cmppad(byte[] s){
	int length;
	int i=0;
	int j = 0;
	while(s[j] == s[0])
	{
		i = i+1;
		j++;
	}
	//System.out.println(i);
	length = i-(87+4)%16;
	//System.out.println(length);
	return length;
	
}
public static boolean isReadReceipt(String messageText) {
	if (messageText.startsWith(READRECEIPT_MESSAGE) == true) {
		return true;
	} else {
		return false;
	}
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
public static byte guess(byte[] s, String ss, String privatekey, int len, int pos,String deinput) throws Exception{ //guess the last sixth byte of c2
	int length;
	byte x = 0;
	length = s.length;
	//pos = len + 1;
	byte y =(byte) len;
	String[] c64 = ss.split(" ");
	//xor last 5 bytes of c2 with 0x05, which padding is 0x05
	for (int i = 1;i<=len;i++){
		s[length - i] = (byte) (s[length - i]^y);
	}
	//String post is the readrecepit
	//String get = sendGet("http://127.0.0.1:80/getMessages/bob");
	//JSONObject obj1 = new JSONObject(get);
    //String msg = obj1.getString("messages");
	//int index=msg.indexOf("e\":\"");
    //String deinput = msg.substring(index+4, msg.length()-3);
	//System.out.println(isReadReceipt(post));
	while ((isReadReceipt(deinput) == false) && (x <=255))
	{
		x++;
		s[length - len-1] = (byte) (s[length - len-1]^x);
		for(int j = 1;j<=(len+1);j++){
			s[length - j] = (byte) (s[length - j]^(len+1));
		}
		String newc2 = Base64.getEncoder().encodeToString(s);
		String sign = resign(privatekey, c64[0],newc2);
		String post = sendPostmsg("http://127.0.0.1:80/sendMessage/sssss",sign,"bob",2);
		deinput = sendGet("http://127.0.0.1:80/getMessages/sssss");
		//x++;
	}
	return (byte) (x^s[length - pos]^pos);
}
public static String resign(String inputPrivateKey,String c1, String c2) throws Exception 
{
	
	byte[] privateKeyByte= Base64.getDecoder().decode(inputPrivateKey);
	PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);  
    KeyFactory factory = KeyFactory.getInstance("DSA");  
    PrivateKey createdPrivateKey = factory.generatePrivate(keySpec);
    Signature signature = Signature.getInstance("DSA");  
    signature.initSign(createdPrivateKey);  
    signature.update((c1+" "+ c2).getBytes("UTF-8"));  
    return c1+" "+c2+" "+Base64.getEncoder().encodeToString(signature.sign()).replaceAll("\r|\n", "");
	
}

}
