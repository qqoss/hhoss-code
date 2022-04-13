package com.hhoss.hash;

import com.hhoss.code.HexCoder;
import com.hhoss.code.coder.Base64;

public class MD5 extends Hash {
	private static final String ALGORITHM = "MD5";
	
	public static byte[] hash(byte[] data) {
		return hash(ALGORITHM,data);
	}
	
	public static byte[] hash(String str) {
		return hash(ALGORITHM,str.getBytes());
	}

	public static String toHex(String s) {
		return HexCoder.toHex(hash(s));
	}

	public static String toHEX(String s) {
		return HexCoder.toHEX(hash(s));
	}

	public static String toHex(byte[] s) {
		return HexCoder.toHex(hash(s));
	}

	public static String toHEX(byte[] s) {
		return HexCoder.toHEX(hash(s));
	}

	public static String toBase64(String s) {
		return Base64.encodeBytes(hash(s));
	}

	public static String toBase64(byte[] s) {
		return Base64.encodeBytes(hash(s));
	}

}
