package com.hhoss.util.coder;

public class Base64 {
	public static byte[] encode(byte[] bytes){
		return java.util.Base64.getEncoder().encode(bytes);
		//return org.apache.commons.codec.binary.Base64.encodeBase64(bytes);
		//return org.bouncycastle.util.encoders.Base64.encode(bytes);
	}
	
	public static byte[] decode(byte[] bytes){
		return java.util.Base64.getMimeDecoder().decode(bytes);
		//return org.apache.commons.codec.binary.Base64.decodeBase64(bytes);
		//return org.bouncycastle.util.encoders.Base64.decode(bytes);
		//return (new sun.misc.BASE64Decoder()).decodeBuffer(key);
	}
	
	public static String encode(String src){
		return new String(encode(src.getBytes()));
	}
	
	public static byte[] encodeString(String src){
		return encode(src.getBytes());
	}
	
	public static String encodeBytes(byte[] bytes){
		return new String(encode(bytes));
	}
	
	public static String decode(String str){
		return new String(decode(str.getBytes()));
	}

	
	public static byte[] decodeString(String str){
		return decode(str.getBytes());
	}
	
	public static String decodeToHex(String str){
		byte[] b = decode(str.getBytes());
		return HexCoder.toHex(b);
	}
	
	public static String decodeToHEX(String str){
		byte[] b = decode(str.getBytes());
		return HexCoder.toHEX(b);
	}
	
	public static String decodeBytes(byte[] bytes){
		return new String(decode(bytes));
	}
	
	@SuppressWarnings("unchecked")
	public static <T> T encodeTo(T src){
		if(src instanceof byte[]){
			return (T)encode((byte[])src);
		}else if(src instanceof String){
			return (T)encode((String)src);
		}
		throw new IllegalArgumentException("params must by byte[] or String");
	}
	
	@SuppressWarnings("unchecked")
	public static <T> T decodeTo(T src){
		if(src instanceof byte[]){
			return (T)decode((byte[])src);
		}else if(src instanceof String){
			return (T)decode((String)src);
		}
		throw new IllegalArgumentException("params must by byte[] or String");
	}
	
	public static void main(String[] args) throws Exception{
		String src = "somekeys?$1";
		byte[] b =src.getBytes();
		System.out.println(encode(src));
		System.out.println(decode(encode(src)));
		
		//System.out.println( (new sun.misc.BASE64Encoder()).encodeBuffer(b));
		//System.out.println((new sun.misc.BASE64Decoder()).decodeBuffer(src));
		//System.out.println(org.bouncycastle.util.encoders.Base64.decode(bytes));

	}
}
