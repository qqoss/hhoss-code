package com.hhoss.util.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;
import java.util.Map.Entry;

/**
 * 
 * @author kejun
 * 
 */
public final class Digester {

	private static final String ALGORITHM = "MD5";

	private static final char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	private static final char[] HEXDigits = { '0', '1', '2', '3', '4', '5',	'6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	/**
	 * encode string
	 * 
	 * @param algorithm
	 * @param str
	 * @return String
	 */
	public static String encode(String algorithm, String str) {
		if (str == null) {
			return null;
		}
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
			return getFormattedText(messageDigest.digest(str.getBytes()));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	/**
	 * encode By MD5
	 * 
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
	 * encode By MD5
	 * 
	 * @param str
	 * @return String
	 */
	public static String encodeByMD5(String str) {
		if (str == null) {
			return null;
		}
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM);
			messageDigest.update(str.getBytes());
			return getFormattedTEXT(messageDigest.digest());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	/**
	 * encode By MD5
	 * 
	 * @param str
	 * @return String
	 */
	public static String encodeByMd5(String str) {
		if (str == null) {
			return null;
		}
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM);
			messageDigest.update(str.getBytes());
			return getFormattedText(messageDigest.digest());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}
	

	public final static String md5(String s) {
		String resultString = null;
		try {
			byte[] btInput = s.getBytes();
			// 获得MD5摘要算法的 MessageDigest 对象
			MessageDigest mdInst = MessageDigest.getInstance("md5");
			// 使用指定的字节更新摘要
			mdInst.update(btInput);
			// 获得密文
			byte[] md = mdInst.digest();
			// 把密文转换成十六进制的字符串形式
			resultString = new String(bytesToChars(md));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return resultString;
	}

	public static String MD5(String s) {
		try {
			byte[] md = MessageDigest.getInstance("MD5").digest(s.getBytes());
			return new String(bytesToCHARS(md));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	// 转换字节数组为16进制字串
	public static char[] bytesToChars(byte[] b) {
		int len = b.length;
		char[] chrs = new char[len * 2];
		for (int i = 0; i < len; i++) {
			byte bi = b[i];
			chrs[2 * i] = hexDigits[bi >>> 4 & 0xf];
			chrs[2 * i + 1] = hexDigits[bi & 0xf];
		}
		return chrs;
	}

	// 转换字节数组为16进制字串
	public static char[] bytesToCHARS(byte[] b) {
		int len = b.length;
		char[] chrs = new char[len * 2];
		for (int i = 0; i < len; i++) {
			int bi = b[i];
			chrs[2 * i] = HEXDigits[bi >>> 4 & 0xf];
			chrs[2 * i + 1] = HEXDigits[bi & 0xf];
		}
		return chrs;
	}

	// 转换字节数组为16进制字串
	public static char[] bytesToCHARS2(byte[] b) {
		int len = b.length;
		char[] chrs = new char[len * 2];
		for (int i = 0; i < len; i++) {
			int bi = b[i];
			if (bi < 0) {
				bi += 256;
			}
			chrs[2 * i] = HEXDigits[bi / 16];
			chrs[2 * i + 1] = HEXDigits[bi % 16];
		}
		return chrs;
	}
	
	 /**将二进制转换成16进制 
    * @param buf 
    * @return 
    */  
   public static String bytesToHex(byte[] b) {  
           StringBuffer sb = new StringBuffer();  
           for (int i = 0; i < b.length; i++) {  
                   String hex = Integer.toHexString(b[i] & 0xFF);  
                   if (hex.length() == 1) {  
                           hex = "0" + hex;  
                   }  
                   sb.append(hex);  
           }  
           return sb.toString();  
   }  
	 /**将二进制转换成16进制 
    * @param b 
    * @return 
    */  
   public static String bytesToHEX(byte[] b) {  
           StringBuffer sb = new StringBuffer();  
           for (int i = 0; i < b.length; i++) {  
                   String hex = Integer.toHexString(b[i] & 0xFF);  
                   if (hex.length() == 1) {  
                           hex = "0" + hex;  
                   }  
                   sb.append(hex.toUpperCase());  
           }  
           return sb.toString();  
   }  
   
	// 返回形式只为数字
	public static String byteToNumber(byte b) {
		int iRet = b;
		System.out.println("iRet1=" + iRet);
		if (iRet < 0) {
			iRet += 256;
		}
		return String.valueOf(iRet);
	}

	private static final String[] strDigits = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F" };
	// 转换字节数组为16进制字串
	public static String[] bytesToStrings(byte[] b) {
		int len = b.length;
		String[] strs = new String[len * 2];
		for (int i = 0; i < len; i++) {
			int bi = b[i];
			if (bi < 0) {
				bi += 256;
			}
			strs[2 * i] = strDigits[bi / 16];
			//strs[2 * i] = Integer.toHexString(bi & 0xFF);  
			strs[2 * i + 1] = strDigits[bi % 16];
		}
		return strs;
	}

    /**将16进制转换为二进制 
     * @param hexStr 
     * @return 
     */  
    public static byte[] hexStr2Byte(String hexStr) {  
            if (hexStr.length() < 1)  
                    return null;  
            byte[] result = new byte[hexStr.length()/2];  
            for (int i = 0;i< result.length; i++) {  
                    int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);  
                    int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);  
                    result[i] = (byte) (high * 16 + low);  
            }  
            return result;  
    } 
  

	/**
	 * Takes the raw bytes from the digest and formats them correct.
	 * 
	 * @param bytes
	 *            the raw bytes from the digest.
	 * @return the formatted bytes.
	 */
	public static String getFormattedText(byte[] bytes) {
		int len = bytes.length;
		StringBuilder buf = new StringBuilder(len * 2);
		// 把密文转换成十六进制的字符串形式
		for (int j = 0; j < len; j++) {
			buf.append(hexDigits[(bytes[j] >> 4) & 0x0f]);
			buf.append(hexDigits[bytes[j] & 0x0f]);
		}
		return buf.toString();
	}

	/**
	 * Takes the raw bytes from the digest and formats them correct.
	 * 
	 * @param bytes
	 *            the raw bytes from the digest.
	 * @return the formatted bytes.
	 */
	public static String getFormattedTEXT(byte[] bytes) {
		int len = bytes.length;
		StringBuilder buf = new StringBuilder(len * 2);
		// 把密文转换成十六进制的字符串形式
		for (int j = 0; j < len; j++) {
			buf.append(HEXDigits[(bytes[j] >> 4) & 0x0f]);
			buf.append(HEXDigits[bytes[j] & 0x0f]);
		}
		return buf.toString();
	}
	
	//please ensure map.remove("sign") is invoked first;
	public static String getValuesSortedByKey(Map<String,Object> map,String spliter){
		Map<String,Object> sortedMap = map;
		if(!(map instanceof TreeMap)){
			sortedMap = new TreeMap<>();
			sortedMap.putAll(map);
		}
		StringBuilder sb = new StringBuilder(spliter);
		for(Entry<String,Object> ent:sortedMap.entrySet()){
			sb.append(ent.getValue()==null?"":ent.getValue().toString()).append(spliter);
		}
		return sb.toString();
	}

	public static void main(String[] args) {
		System.out.println("111111 MD5  :" + Digester.encodeByMD5("111111"));
		System.out.println("111111 MD5  :" + Digester.encode("MD5", "111111"));
		System.out.println("111111 SHA1 :" + Digester.encode("SHA1", "111111"));
		System.out.println(Digester.encode("MD5","20121221"));
		System.out.println(Digester.encode("MD5","加密"));
		System.out.println(Digester.encodeByMD5("20121221"));
		System.out.println(Digester.encodeByMD5("加密"));
	}
	
public static byte[] converLongToBytes(long l) {
		
		byte[] b = new byte[8];
		b = java.lang.Long.toString(l).getBytes();
		return b;
	}
	
	public static long converBytesToLong(byte[] b) {
		
		long l = 0L;
		l = java.lang.Long.parseLong(new String(b));
		return l;
	}

    public static long bytesToLong(byte[] bytes) {
    	if(bytes.length>8){
    		throw new IllegalArgumentException("bytes for long should less than 8 bytes");
    	}
        long retVal = (bytes[0] & 0xFF);
        for (int i = 1; i < Math.min(bytes.length, 8); i++) {
          retVal |= (bytes[i] & 0xFFL) << (i * 8);
        }
        return retVal;
      }

	public static byte[] longToBytes(long number) {
		long temp = number;		
		byte[] b = new byte[8];
		for (int i = b.length - 1; i > -1; i--)	{
			b[i] = new Long(temp & 0xff).byteValue();
			temp = temp >> 8;
		}
		return b;
	}

}