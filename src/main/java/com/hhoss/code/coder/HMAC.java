package com.hhoss.code.coder;

import java.math.BigInteger;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.hhoss.util.coder.Base64;

/**
 * 基础加密组件
 * 
 * @author 梁栋
 * @version 1.0
 * @since 1.0
 */
public abstract class HMAC {

	/**
	 * MAC算法可选以下多种算法
	 * 
	 * <pre>
	 * HmacMD5  
	 * HmacSHA1  
	 * HmacSHA256  
	 * HmacSHA384  
	 * HmacSHA512
	 * </pre>
	 */
	public static final String KEY_MAC = "HmacMD5";

	/**
	 * 初始化HMAC密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static String initMacKey() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_MAC);

		SecretKey secretKey = keyGenerator.generateKey();
		return Base64.encodeBytes(secretKey.getEncoded());
	}

	/**
	 * HMAC加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptHMAC(byte[] data, String key) throws Exception {

		SecretKey secretKey = new SecretKeySpec(Base64.decodeString(key), KEY_MAC);
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);

		return mac.doFinal(data);

	}

	public static void main(String[] args) {
		String inputStr = "简单加密";
		System.err.println("原文:\n" + inputStr);

		try {
			byte[] inputData = inputStr.getBytes();
			String key = HMAC.initMacKey();
			System.err.println("Mac密钥:\n" + key);
			BigInteger mac = new BigInteger(HMAC.encryptHMAC(inputData,
					inputStr));
			System.err.println("HMAC:\n" + mac.toString(16));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
