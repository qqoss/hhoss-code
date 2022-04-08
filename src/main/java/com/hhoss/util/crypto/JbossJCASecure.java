package com.hhoss.util.crypto;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class JbossJCASecure {
	private static final byte[] kbytes = "jaas is the way".getBytes();
	
	private static String encode(String secret) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("Blowfish");
		cipher.init(1, new SecretKeySpec(kbytes, "Blowfish"));
		
		byte[] encoding = cipher.doFinal(secret.getBytes());
		BigInteger n = new BigInteger(encoding);
		return n.toString(16);
	}

	private static char[] decode(String secret) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("Blowfish");
		cipher.init(2, new SecretKeySpec(kbytes, "Blowfish"));
		
		BigInteger n = new BigInteger(secret, 16);
		byte[] encoding = n.toByteArray();
		byte[] decode = cipher.doFinal(encoding);
		return new String(decode).toCharArray();
	}

	public static void main(String[] args) throws Exception {
		String encode = encode(args==null||args.length==0?"JCA123456":args[0]);
		System.out.println("Encoded password: " + encode);
		System.out.println("decoded password: " + new String(decode("-38c30fc0d83f9e39908220a30101d023")));
	}
}