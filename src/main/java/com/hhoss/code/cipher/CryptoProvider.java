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

public class CryptoProvider extends TokenProvider{
	private static final Logger logger = Logger.get();
	private static final long serialVersionUID = 4046355171903493723L;
	private String algorithm="01";
	private String secretkey="01";
	
	public CryptoProvider(String... params){
		if( params==null||params.length<1 ){return;}
		if( params[0].length()>1 ){
			this.algorithm = params[0];
		}
		if( params.length>1&&params[1].length()>1 ){
			this.secretkey = params[1];
		}
	}

	@Override public String getName() {return PREFIX+"crypto";}	
	/**
	 * $crypto$aes1$keyId$... <br />
	 * $cipher$arithmIdx$params$... <br />
	 * $secret$... <br />
	 * enctyptData
	 */
	@Override public String get(String val) {
		if(val==null){return null;}
		String[] parts  = val.split("\\$");
		String encode = parts[parts.length-1];
		String secret = (parts.length>2)? parts[parts.length-2]:secretkey;
			   secret = secret.length()<6?secret:secretkey;
		String arithm = (parts.length>4)? parts[2]:(parts.length>3)?parts[1]:algorithm;
			   arithm = arithm.length()<6?arithm:algorithm;
		return decrypt(encode,secret,arithm);
	}
	
	private String decrypt(String enc, String key, String alg ){
		try{
			SecretKeySpec ks = new SecretKeySpec(getBytes(key),CIP.get(alg));		
			Cipher cipher = Cipher.getInstance(CIP.get(alg));
			cipher.init(Cipher.DECRYPT_MODE, ks, new SecureRandom());
			return new String(cipher.doFinal(Base64.decodeString(enc)));
		}catch(Exception e){
			logger.warn("解密[{}]出错:{}",enc,e.getMessage());
		}
		return enc;
	}
	
	private byte[] getBytes(String key){
		byte[] bytes = KEY.get(key.length()>4?"01":key).getBytes();
		return Arrays.copyOf(bytes,(bytes.length/8)*8);
	}

}