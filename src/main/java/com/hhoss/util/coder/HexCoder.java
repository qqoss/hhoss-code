package com.hhoss.util.coder;

public class HexCoder {

	private static final char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	private static final char[] HEXDigits = { '0', '1', '2', '3', '4', '5',	'6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	
	// 转换字节数组为16进制小写字串
	public static char[] toChars(byte[] b) {
		int len = b.length;
		char[] chrs = new char[len * 2];
		for (int i = 0; i < len; i++) {
			byte bi = b[i];
			chrs[2 * i] = hexDigits[bi >>> 4 & 0xf];
			chrs[2 * i + 1] = hexDigits[bi & 0xf];
		}
		return chrs;
	}

	// 转换字节数组为16进制大写字串
	public static char[] toCHARS(byte[] b) {
		int len = b.length;
		char[] chrs = new char[len * 2];
		for (int i = 0; i < len; i++) {
			byte bi = b[i];
			chrs[2 * i] = HEXDigits[bi >>> 4 & 0xf];
			chrs[2 * i + 1] = HEXDigits[bi & 0xf];
		}
		return chrs;
	}

	// 转换字节数组为16进制字串
	public static char[] toCHARS2(byte[] b) {
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

	public static String toHex(byte[] b) {
		return b==null?null:new String(toChars(b));
	}
	public static String toHEX(byte[] b) {
		return b==null?null:new String(toCHARS(b));
	}
	
	 /**将二进制转换成16进制 
    * @param buf 
    * @return 
    */  
	@Deprecated
   public static String toHex2(byte[] b) {  
		int len = b.length;
		StringBuilder buf = new StringBuilder(len * 2);
		// 把密文转换成十六进制的字符串形式
		for (int j = 0; j < len; j++) {
			buf.append(HEXDigits[(b[j] >> 4) & 0x0f]);
			buf.append(HEXDigits[b[j] & 0x0f]);
		}
		return buf.toString();
   }
   
	/**将二进制转换成16进制 
    * @param b 
    * @return 
    */  
	@Deprecated
   public static String toHEX2(byte[] b) {  
		int len = b.length;
		StringBuilder buf = new StringBuilder(len * 2);
		// 把密文转换成十六进制的字符串形式
		for (int j = 0; j < len; j++) {
			buf.append(HEXDigits[(b[j] >> 4) & 0x0f]);
			buf.append(HEXDigits[b[j] & 0x0f]);
		}
		return buf.toString();
   }  
   
	@Deprecated
	private static String getFormattedText(byte[] b) {
		StringBuffer sb = new StringBuffer();  
       for (int i = 0; i < b.length; i++) {  
           String hex = Integer.toHexString(b[i] & 0xFF);  
           if (hex.length() == 1) {  
        	   	sb.append("0");  
           }  
           sb.append(hex);  
       }  
       return sb.toString();  
	}
	
	@Deprecated
	private static String getFormattedTEXT(byte[] b) {
		StringBuffer sb = new StringBuffer();  
           for (int i = 0; i < b.length; i++) {  
               String hex = Integer.toHexString(b[i] & 0xFF);  
               if (hex.length() == 1) {  
	           	   sb.append("0");  
	           }  
               sb.append(hex.toUpperCase());  
           }  
           return sb.toString();  
	}

    /**将16进制转换为二进制 
     * @param hexStr 
     * @return 
     */  
    public static byte[] hexToBytes(String hexStr) {  
        if (hexStr.length() < 1 || hexStr.length() %2==1)  
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
	 * long to  bytes array
	 * @param long
	 * @return bytes
	 */
	public static byte[] longToBytes(long number) {
		long temp = number;		
		byte[] b = new byte[8];
		for (int i = b.length - 1; i > -1; i--)	{
			b[i] = new Long(temp & 0xff).byteValue();
			temp = temp >> 8;
		}
		return b;
	}
	
	/**
	 * bytes array to long
	 * @param bytes
	 * @return long
	 */
    public static long byteToLong(byte[] bytes) {
    	if(bytes.length>8){
    		throw new IllegalArgumentException("bytes for long should less than 8 bytes");
    	}
        long retVal = (bytes[0] & 0xFF);
        for (int i = 1; i < Math.min(bytes.length, 8); i++) {
          retVal |= (bytes[i] & 0xFFL) << (i * 8);
        }
        return retVal;
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

}
