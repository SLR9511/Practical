package hw3;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

import org.json.JSONObject;



//import hw3.MessageEncryptor;



public class Main {
	public static final String PUBLIC_KEY_DSA="publicDSAKey";
	public static final String PRIVATE_KEY_DSA="privateDSAKey";
	public static final String PUBLIC_KEY_RSA = "publicRSAKey";
	public static final String PRIVATE_KEY_RSA = "privateRSAKey";
	
	//public static MessageEncryptor mEncryptor;
	public static void main(String[] args) throws Exception{
		Part1 test = new Part1();
		Part2 test1 = new Part2();
		Part3 test2 = new Part3();
		
		
		//if need to run part3 please remain this part of code
		/*String get = test2.sendGet("http://127.0.0.1:80/getMessages/bob");
		System.out.println(get);
		JSONObject obj1 = new JSONObject(get);
        String msg = obj1.getString("messages");
        int n = 0;
        while(n == 0)
		{
        	String get1 = test1.sendGet("http://127.0.0.1:80/getMessages/bob");
        	JSONObject obj2 = new JSONObject(get1);
             msg = obj2.getString("messages");
             n = obj2.getInt("numMessages");
             //System.out.println(n);
		}
        //System.out.println(msg);
        int index=msg.indexOf("e\":\"");
        String deinput = msg.substring(index+4, msg.length()-3);
        String[] c64 = deinput.split(" ");
        byte[] c2 = test2.getc2(c64[1]);
        int len = c2.length;
        byte postion = -15;
        System.out.println(len);
        //compute the padding length;
        int pad = test2.cmppad(c2);
        
      //CREAT DSA AND RSA KEYS
        Map<String,String> myCreateKeyDSA=test1.createDsaKeys();
		String publicKeyDSA=myCreateKeyDSA.get(PUBLIC_KEY_DSA);
		String privateKeyDSA=myCreateKeyDSA.get(PRIVATE_KEY_DSA);
		Map<String,String> myCreateKeyRSA=test1.createRsaKeys();
		String publicKeyRSA=myCreateKeyRSA.get(PUBLIC_KEY_RSA);
		String privateKeyRSA=myCreateKeyRSA.get(PRIVATE_KEY_RSA);
		String key = publicKeyRSA + "%" +publicKeyDSA;
		byte position = test2.guess(c2, deinput, privateKeyDSA, pad, pad+1,deinput);
		System.out.println("The last sixth byte is :");
		//byte bytes = position;
	    StringBuilder sb = new StringBuilder();
	    
	        sb.append(String.format("%02X ", postion));
	    
	    System.out.println(sb.toString());*/
        //end of part3 code*/
        
		//String num;
	    //if need to run part2 and part1, please remain this part of code and comment code above
		ServerConnection mServerConnection = new ServerConnection();
		MessageEncryptor mEncryptor = new MessageEncryptor("yunchao111");
		String get = test1.sendGet("http://127.0.0.1:80/getMessages/bob");
		
		
	    
		JSONObject obj1 = new JSONObject(get);
        String msg = obj1.getString("messages");
        int n = 0;
        while(n == 0)
		{
        	String get1 = test1.sendGet("http://127.0.0.1:80/getMessages/bob");
        	JSONObject obj2 = new JSONObject(get1);
             msg = obj2.getString("messages");
             n = obj2.getInt("numMessages");
             System.out.println(n);
		}
        System.out.println(msg);
        int index=msg.indexOf("e\":\"");
        String deinput = msg.substring(index+4, msg.length()-3);
        System.out.println(deinput);
        
        String[] c64 = deinput.split(" ");
        String c1 = c64[0]; //get c1 with base64 encoded;
        byte[] c2 = test1.getc2(c64[1]);
        String senderID = test1.getsender(msg);
        System.out.println(senderID);
        //int length = senderID.length();
        String newc2 = test1.xor(c2, senderID);
        
        //CREAT DSA AND RSA KEYS
        Map<String,String> myCreateKeyDSA=test1.createDsaKeys();
		String publicKeyDSA=myCreateKeyDSA.get(PUBLIC_KEY_DSA);
		String privateKeyDSA=myCreateKeyDSA.get(PRIVATE_KEY_DSA);
		Map<String,String> myCreateKeyRSA=test1.createRsaKeys();
		String publicKeyRSA=myCreateKeyRSA.get(PUBLIC_KEY_RSA);
		String privateKeyRSA=myCreateKeyRSA.get(PRIVATE_KEY_RSA);
		String key = publicKeyRSA + "%" +publicKeyDSA;
		
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA",
	            "SUN");
	        SecureRandom random = SecureRandom.getInstance("SHA1PRNG",
	            "SUN");

	        keyGen.initialize(1024, random);

	        KeyPair pair = keyGen.generateKeyPair();
	        PrivateKey priv = pair.getPrivate();
	        PublicKey pub = pair.getPublic();
	        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");

	        dsa.initSign(priv);
	        dsa.update((c1+newc2).getBytes("UTF-8"));
	        String sign = c1 + " "+newc2 + " "+Base64.getEncoder().encodeToString(dsa.sign());
		//System.out.println("keys been post is "+key);
		//send public keys to server
		
		String alicekey = test1.sendGet("http://127.0.0.1:80/lookupKey/alice");
		System.out.println(alicekey);
		String keys = test1.getKey(alicekey);
		String[] akey = keys.split("%");
		System.out.println(akey[0]);
		String postkey = akey[0] + "%" + Base64.getEncoder().encodeToString(pub.getEncoded());;
		String sendkey = test1.sendkey("http://127.0.0.1:80/registerKey/sssss", key);
		//get sssss keys
		//String senderkey = test1.sendGet("http://127.0.0.1:80/lookupKey/sssss");
		//System.out.println(senderkey);
		
		//resign c2 using privateDSAkey
        //String sign = test1.re(c1, newc2, privateKeyDSA);
        String sign1 = test1.resign(privateKeyDSA, c1, newc2);
        System.out.println("post msg is "+sign1);
        //System.out.println(sign1);
        //String postoutput = test1.sendPostmsg("http://jmessage.server.isi.jhu.edu:80/sendMessage/yunchao111",sign,"yunchao",1);
        //post resign msg to bob
        String postoutput1 = test1.sendPostmsg("http://127.0.0.1:80/sendMessage/sssss",sign1,"bob",2);
	    
	    //end of part1 and part2 code.
        
        
	}
}