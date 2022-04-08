package com.hhoss.util.crypto;

import com.hhoss.Constant;
import com.hhoss.util.HMap;

public interface CipherConstants extends Constant{
	
	/**
	 * cipher information provider holders
	 * todo from cache and dbms
	 */
	//res.crypto.cipher.01
	static final HMap<String> CIP = 
			 new HMap<String>(
					 "01","DES",
					 "02","AES",
					 "03","RSA",
					 "04","DESede",
					 "des","DES",
					 "aes","AES",
					 "rsa","RSA",
					 "3des","DESede"
					);
	/**
	 * key encrypt yard
	 */
	//res.crypto.secret.01
	static final HMap<String> KEY = 
			 new HMap<String>(
					 "01","ENCRYPT@ZHENG",
					 "02","ENCRYPT@KEJUN",
					 "03","AESKEY3ZHENG@CREDIT2GO",
					 "04","AESKEY4KEJUN@CREDIT2GO"
					);
}
