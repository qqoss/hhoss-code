package com.hhoss.code.cipher;

import static com.hhoss.code.crypto.CipherConstants.CIP;
import static com.hhoss.code.crypto.CipherConstants.KEY;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.hhoss.code.coder.Base64;
import com.hhoss.jour.Logger;
import com.hhoss.util.token.TokenProvider;
/**
 * @author kejun
 * return the map value, if map value isn't string, return null.
 */

public class CipherProvider extends TokenProvider{
	private static final Logger logger = Logger.get();
	private static final long serialVersionUID = 4046355171903493723L;
	public CipherProvider(){}
	
	@Override public String getName() {return PREFIX+"cipher";}	
	/**
	 * $pass <br />
	 * $secret$... <br />
	 * enctyptData
	 */
	@Override public String get(String val) {
		if(val==null){return null;}
		String[] parts  = val.split("\\$");
		String encode = parts[parts.length-1];
		try{
			SecretKeySpec ks = new SecretKeySpec(getBytes("cipher"),CIP.get("01"));		
			Cipher cipher = Cipher.getInstance(CIP.get("01"));
			cipher.init(Cipher.DECRYPT_MODE, ks, new SecureRandom());
			return new String(cipher.doFinal(Base64.decodeString(encode)));
		}catch(Exception e){
			logger.warn("解密[{}]出错:{}",encode,e.getMessage());
		}
		return encode;
	}
	
	private byte[] getBytes(String key){
		byte[] bytes = KEY.get(key.length()>4?"01":key).getBytes();
		return Arrays.copyOf(bytes,(bytes.length/8)*8);
	}
	
}