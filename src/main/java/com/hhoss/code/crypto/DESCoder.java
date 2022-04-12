package com.hhoss.code.crypto;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import com.hhoss.code.coder.Base64;

/**
 * @author kejun
 *
 */
public class DESCoder {

	public static final String ALGORITHM = "DES";

	/**
	 * 转换密钥<br>
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	private static Key toKey(byte[] key) throws Exception {
		DESKeySpec dks = new DESKeySpec(key);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
		SecretKey secretKey = keyFactory.generateSecret(dks);

		// 当使用其他对称加密算法时，如AES、Blowfish等算法时，用下述代码替换上述三行代码
		// SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);

		return secretKey;
	}
	/**
	 * 加密
	 * 
	 * @param data source
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String data, String key) throws Exception {
		byte[] b = DESCoder.encrypt(data.getBytes(), key);
		return Base64.encodeBytes(b);

	}
	public static byte[] encrypt(byte[] data, String key) throws Exception {
		Key k = toKey(key.getBytes());
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, k, new SecureRandom());

		return cipher.doFinal(data);
	}

	/**
	 * 解密
	 * 
	 * @param data encrypted base64 String
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String data, String key) throws Exception {
		byte[] b = decrypt(Base64.decodeString(data),key);
		return new String(b);

	}
	
	public static byte[] decrypt(byte[] data, String key) throws Exception {
		Key k = toKey(key.getBytes());

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, k, new SecureRandom());

		return cipher.doFinal(data);
	}

	/**
	 * 生成密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static String initKey() throws Exception {
		return initKey(null);
	}

	/**
	 * 生成密钥
	 * 
	 * @param seed
	 * @return
	 * @throws Exception
	 */
	public static String initKey(String seed) throws Exception {
		SecureRandom secureRandom = null;

		if (seed != null) {
			secureRandom = new SecureRandom(Base64.decodeString(seed));
		} else {
			secureRandom = new SecureRandom();
		}

		KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
		kg.init(secureRandom);

		SecretKey secretKey = kg.generateKey();

		return Base64.encodeBytes(secretKey.getEncoded());
	}

	public static void main(String[] args) {
		try {
			String inputStr = "credit2go";
			String key = DESCoder.initKey();
			key= "ENCRYPT@ZHENGKEJUN";
			System.err.println("原文:\t" + inputStr);
			System.err.println("密钥:\t" + key);
			byte[] inputData = inputStr.getBytes();
			inputData = DESCoder.encrypt(inputData, key);
			System.err.println("加密后:\t" + new String(Base64.encode(inputData)));
			byte[] outputData = DESCoder.decrypt(inputData, key);
			String outputStr = new String(outputData);
			System.err.println("解密后:\t" + outputStr);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
