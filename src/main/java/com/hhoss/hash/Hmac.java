package com.hhoss.hash;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import com.hhoss.util.Base64;

/**
 * 
 * @author Kejun
 * @version 1.0
 * @since 1.0
 */
public abstract class Hmac {

	/**
	 * MAC Algorithm
	 * 
	 * <pre>
		HmacMD5
		HmacSHA1
		HmacSHA224
		HmacSHA256
		HmacSHA384
		HmacSHA512
		HmacSHA512/224
		HmacSHA512/256
		HmacSHA3-224
		HmacSHA3-256
		HmacSHA3-384
		HmacSHA3-512
	 * </pre>
	 */

	/**
	 * initial HMAC key
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] genKey(String algorithm) throws GeneralSecurityException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		Key key = keyGenerator.generateKey();
		return key.getEncoded();
	}

	public static Key genKey(String algorithm, byte[] seed) throws GeneralSecurityException {
		return new SecretKeySpec(seed, algorithm);
	}

	/**
	 * @param algorithm 
	 * @param data to hmac hash
	 * @param seed to generated Secret Key
	 * @return
	 * @throws GeneralSecurityException 
	 * @throws Exception
	 */
	public static byte[] hmac(String algorithm, byte[] data, byte[] seed) throws GeneralSecurityException {
		Key key = genKey(algorithm,seed);
		Mac mac = Mac.getInstance(algorithm);
		mac.init(key);
		return mac.doFinal(data);
	}

	public static byte[] hmac(Key key, byte[] data) throws GeneralSecurityException {
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		return mac.doFinal(data);
	}


	public static byte[] hmacSha512(byte[] key, byte[] input) {
		HMac hMac = new HMac(new SHA512Digest());
		hMac.init(new KeyParameter(key));
		hMac.update(input, 0, input.length);
		byte[] out = new byte[64];
		hMac.doFinal(out, 0);
		return out;
	}

	public static byte[] hmacSha256(byte[] key, byte[] input) {
		HMac hMac = new HMac(new SHA256Digest());
		hMac.init(new KeyParameter(key));
		hMac.update(input, 0, input.length);
		byte[] out = new byte[32];
		hMac.doFinal(out, 0);
		return out;
	}

	public static void main(String[] args) {
		String inputStr = "simple data";
		System.out.println("data:" + inputStr);
		byte[] inputData = inputStr.getBytes();

		try {
			byte[] key = Hmac.genKey("hmacMD5");
			System.err.println("Mac Key:" + Base64.encodeBytes(key));
			BigInteger mac = new BigInteger(Hmac.hmac("hmacMD5",inputData,key));
			System.err.println("HMAC:" + mac.toString(16));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	

}
