package com.hhoss.util.coder;

import java.security.MessageDigest;

/**
 * 
 * @author kejun
 * 
 */
public final class Digester  {

	private static final String ALGORITHM = "MD5";


	/**
	 * encode By MD5
	 * @param str
	 * @return byte[]
	 */
	public static byte[] encode(String algorithm,byte[] data) {
		if (data == null) {
			return null;
		}
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
			return messageDigest.digest(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * encode string
	 * 
	 * @param algorithm
	 * @param str
	 * @return String
	 */
	public static String encode2Hex(String algorithm, String str) {
		byte[] b=encode(algorithm,str.getBytes());
		return HexCoder.toHex(b);
	}

	/**
	 * encode string
	 * 
	 * @param algorithm
	 * @param str
	 * @return String
	 */
	public static String encode2HEX(String algorithm, String str) {
		byte[] b=encode(algorithm,str.getBytes());
		return HexCoder.toHEX(b);

	}

	
	public final static byte[] md5(byte[] s) {
		try {
			/*
			byte[] btInput = s.getBytes();// 获得MD5摘要算法的 MessageDigest 对象
			MessageDigest mdInst = MessageDigest.getInstance("md5");// 使用指定的字节更新摘要
			mdInst.update(btInput);	// 获得密文
			return mdInst.digest();
			*/
			return MessageDigest.getInstance("MD5").digest(s);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public final static byte[] md5String(String s) {
		return md5(s.getBytes());
	}

	public final static String md5Hex(String s) {
		byte[] md = md5String(s);
		return HexCoder.toHex(md);
	}

	public static String md5HEX(String s) {
		byte[] md = md5String(s);
		return HexCoder.toHEX(md);
	}

	public final static String md5Hex(byte[] s) {
		byte[] md = md5(s);
		return HexCoder.toHex(md);
	}

	public static String md5HEX(byte[] s) {
		byte[] md = md5(s);
		return HexCoder.toHEX(md);
	}

	public final static String md5Base64(String s) {
		byte[] md = md5String(s);
		return Base64.encodeBytes(md);
	}

	public final static String md5Base64(byte[] s) {
		byte[] md = md5(s);
		return Base64.encodeBytes(md);
	}
	
	
	public final static byte[] sha1(byte[] code, byte[] salt) {
		try {
			MessageDigest mdInst = MessageDigest.getInstance("SHA-1");
			mdInst.update(code);	// 使用内容信息更新摘要
			if(salt!=null){
				mdInst.update(salt);// 使用随机信息更新摘要
			}
			return mdInst.digest();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public final static byte[] sha1String(String code,String salt) {
		return sha1(code.getBytes(),salt==null?null:salt.getBytes());
	}

	public final static String sha1Hex(String code,String salt) {
		byte[] md = sha1String(code,salt);
		// 把密文转换成十六进制的字符串形式
		return HexCoder.toHex(md);
	}

	public static String sha1HEX(String code,String salt) {
		byte[] md = sha1String(code,salt);
		return HexCoder.toHEX(md);
	}

	public final static String sha1Hex(byte[] code,byte[] salt) {
		byte[] md = sha1(code,salt);
		// 把密文转换成十六进制的字符串形式
		return HexCoder.toHex(md);
	}

	public static String sha1HEX(byte[] code,byte[] salt) {
		byte[] md = sha1(code,salt);
		return HexCoder.toHEX(md);
	}

	public final static String sha1Base64(String code,String salt) {
		byte[] md = sha1String(code,salt);
		return Base64.encodeBytes(md);
	}

	public final static String sha1Base64(byte[] code,byte[] salt) {
		byte[] md = sha1(code,salt);
		return Base64.encodeBytes(md);
	}


	@Deprecated
	private static String encodeByMD5(String str) {
		if (str == null) {
			return null;
		}
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM);
			messageDigest.update(str.getBytes());
			return HexCoder.toHEX(messageDigest.digest());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	@Deprecated
	private static String encodeByMd5(String str) {
		if (str == null) {
			return null;
		}
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM);
			messageDigest.update(str.getBytes());
			return HexCoder.toHex(messageDigest.digest());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}
 	
    public static boolean isEqual(byte[] a, byte[] b) {
    	return MessageDigest.isEqual(a, b);
    }

	public static void main(String[] args) {
		System.out.println("111111 MD5  :" + Digester.md5HEX("111111"));
		System.out.println("111111 MD5  :" + Digester.encode2Hex("MD5", "111111"));
		System.out.println("111111 SHA1 :" + Digester.encode2Hex("SHA1", "111111"));
		System.out.println(Digester.encode2Hex("MD5","20121221"));
		System.out.println(Digester.encode2Hex("MD5","加密"));
		System.out.println(Digester.md5HEX("20121221"));
		System.out.println(Digester.md5HEX("加密"));
	}

}