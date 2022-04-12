package com.hhoss.code.crypto;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

/*字符串 DESede(3DES) 加密*/ 

public class ThreeDesUtil { 

    /** 
     * 3DS加密 
     * 
     * @author liyunlong_88@126.com 
     */ 

    private static final String Algorithm = "DESede/CBC/PKCS5Padding"; // 定义加密算法,可用 
                                                                        // DES,DESede,Blowfish，DESede/CBC/PKCS5Padding 

    // keybyte为加密密钥，长度为24字节 

    // src为被加密的数据缓冲区（源） 
    /* 
     * private static SecretKey deskey = null; 
     * 
     * public static void getKey(byte[] strKey) { try { KeyGenerator _generator 
     * = KeyGenerator.getInstance("DES"); _generator.init(new 
     * SecureRandom(strKey)); deskey = _generator.generateKey(); _generator = 
     * null; } catch (Exception e) { e.printStackTrace(); } } 
     */ 
    public static byte[] encryptMode(String iv, String key, String src) { 

        try { 
            byte[] keybyte = key.getBytes(); 
            byte[] rand = new byte[8]; 
            rand = iv.getBytes(); 
            // 用随即数生成初始向量 

            /* 
             * Random r=new Random(); r.nextBytes(rand); 
             */ 
            IvParameterSpec ivp = new IvParameterSpec(rand); 

            // 生成密钥 

           // SecureRandom sr = new SecureRandom(); 
            DESedeKeySpec dks = new DESedeKeySpec(keybyte); 
            SecretKeyFactory keyFactory = SecretKeyFactory 
                    .getInstance("DESede"); 
            SecretKey securekey = keyFactory.generateSecret(dks); 
            // IvParameterSpec iv = new IvParameterSpec(PASSWORD_IV.getBytes()); 
            /* 
             * Cipher cipher = Cipher.getInstance("DESede"); 
             * cipher.init(Cipher.ENCRYPT_MODE, securekey, ivp, sr); return new 
             * String(Hex.encodeHex(cipher.doFinal(str.getBytes()))); 
             */ 

            // 加密 

            Cipher c1 = Cipher.getInstance(Algorithm); 

            c1.init(Cipher.ENCRYPT_MODE, securekey, ivp); 

            return c1.doFinal(src.getBytes());// 在单一方面的加密或解密 

        } catch (java.security.NoSuchAlgorithmException e1) { 

            // TODO: handle exception 

            e1.printStackTrace(); 

        } catch (javax.crypto.NoSuchPaddingException e2) { 

            e2.printStackTrace(); 

        } catch (java.lang.Exception e3) { 

            e3.printStackTrace(); 

        } 

        return null; 

    } 

    // keybyte为加密密钥，长度为24字节 

    // src为加密后的缓冲区 

    public static byte[] decryptMode(String iv, String key, byte[] src) { 

        try { 
            byte[] srcbytes = src; 
            byte[] keybyte = key.getBytes(); 
            byte[] rand = new byte[8]; 
            rand = iv.getBytes(); 
            // 用随即数生成初始向量 

            /* 
             * Random r=new Random(); r.nextBytes(rand); 
             */ 
            IvParameterSpec ivp = new IvParameterSpec(rand); 

            // 生成密钥 

            SecureRandom sr = new SecureRandom(); 
            DESedeKeySpec dks = new DESedeKeySpec(keybyte); 
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede"); 
            SecretKey securekey = keyFactory.generateSecret(dks); 

            // 解密 

            Cipher c1 = Cipher.getInstance(Algorithm); 

            c1.init(Cipher.DECRYPT_MODE, securekey, ivp); 

            /* 
             * int len = src.getBytes().length; 
             * byte[] zero = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; 
             * if (len < 8) { 
             *  srcbytes = new byte[8]; 
             *  System.arraycopy(src.getBytes(), 0, srcbytes, 0, len); 
             *  System.arraycopy(zero, len, srcbytes, len, 8 - len); 
             * } else { 
             *  srcbytes = src.getBytes(); 
             * } 
             */ 

            return c1.doFinal(srcbytes); 

        } catch (java.security.NoSuchAlgorithmException e1) { 
           e1.printStackTrace(); 
        } catch (javax.crypto.NoSuchPaddingException e2) { 
            e2.printStackTrace(); 
        } catch (java.lang.Exception e3) { 
            e3.printStackTrace(); 
        } 

        return null; 

    } 

    // 转换成十六进制字符串 

    public static String byte2Hex(byte[] b) { 

        String hs = ""; 

        String stmp = ""; 

        for (int n = 0; n < b.length; n++) { 

            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF)); 

            if (stmp.length() == 1) { 

                hs = hs + "0" + stmp; 

            } else { 

                hs = hs + stmp; 

            } 

            if (n < b.length - 1) 
                hs = hs + ":"; 

        } 

        return hs.toUpperCase(); 

    } 

    public static final String encodeHex(byte bytes[]) { 
        StringBuffer buf = new StringBuffer(bytes.length * 2); 
        for (int i = 0; i < bytes.length; i++) { 
            if ((bytes[i] & 0xff) < 16) 
                buf.append("0"); 
            buf.append(Long.toString(bytes[i] & 0xff, 16)); 
        } 
        return buf.toString(); 
    } 

    public static final byte[] decodeHex(String hex) { 
        char chars[] = hex.toCharArray(); 
        byte bytes[] = new byte[chars.length / 2]; 
        int byteCount = 0; 
        for (int i = 0; i < chars.length; i += 2) { 
            int newByte = 0; 
            newByte |= hexCharToByte(chars[i]); 
            newByte <<= 4; 
            newByte |= hexCharToByte(chars[i + 1]); 
            bytes[byteCount] = (byte) newByte; 
            byteCount++; 
        } 
        return bytes; 
    } 

    private static final byte hexCharToByte(char ch) { 
        switch (ch) { 
        case 48: // '0' 
            return 0; 

        case 49: // '1' 
            return 1; 

        case 50: // '2' 
            return 2; 

        case 51: // '3' 
            return 3; 

        case 52: // '4' 
            return 4; 

        case 53: // '5' 
            return 5; 

        case 54: // '6' 
            return 6; 

        case 55: // '7' 
            return 7; 

        case 56: // '8' 
            return 8; 

        case 57: // '9' 
            return 9; 

        case 97: // 'a' 
            return 10; 

        case 98: // 'b' 
            return 11; 

        case 99: // 'c' 
            return 12; 

        case 100: // 'd' 
            return 13; 

        case 101: // 'e' 
            return 14; 

        case 102: // 'f' 
            return 15; 

        case 58: // ':' 
        case 59: // ';' 
        case 60: // '<' 
        case 61: // '=' 
        case 62: // '>' 
        case 63: // '?' 
        case 64: // '@' 
        case 65: // 'A' 
        case 66: // 'B' 
        case 67: // 'C' 
        case 68: // 'D' 
        case 69: // 'E' 
        case 70: // 'F' 
        case 71: // 'G' 
        case 72: // 'H' 
        case 73: // 'I' 
        case 74: // 'J' 
        case 75: // 'K' 
        case 76: // 'L' 
        case 77: // 'M' 
        case 78: // 'N' 
        case 79: // 'O' 
        case 80: // 'P' 
        case 81: // 'Q' 
        case 82: // 'R' 
        case 83: // 'S' 
        case 84: // 'T' 
        case 85: // 'U' 
        case 86: // 'V' 
        case 87: // 'W' 
        case 88: // 'X' 
        case 89: // 'Y' 
        case 90: // 'Z' 
        case 91: // '[' 
        case 92: // '\\' 
        case 93: // ']' 
        case 94: // '^' 
        case 95: // '_' 
        case 96: // '`' 
        default: 
            return 0; 
        } 
    } 

    public static void main(String[] args) { 

        // TODO Auto-generated method stub 

        // 添加新安全算法,如果用JCE就要把它添加进去 

        // Security.addProvider(new com.sun.crypto.provider.SunJCE()); 

        /* 
         * final byte[] keyBytes = { 0x01, 0x02, 0x03, 0x04, 
         * 
         * (byte) 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 
         * 
         * (byte) 0x03, 
         * 
         * (byte) 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 
         * 
         * (byte) 0x00, 0x01, 0x02, 0x03, 
         * 
         * (byte) 0x04 
         * 
         * }; // 24字节的密钥 
         */ 
        String szSrc = "1"; 

        System.out.println("加密前的字符串:" + szSrc); 

        byte[] encoded = encryptMode("12345678", "123456789012345678943210", 
                szSrc); 

        System.out.println("加密后的字符串:" + encodeHex(encoded)); 

        byte[] srcBytes = decryptMode("12345678", "123456789012345678943210", 
                "c5e8faaf1a0e52ae".getBytes()); 

        System.out.println("解密后的字符串:" + (new String(srcBytes))); 

    } 
    
    /**
    
    关于DES加密中的 DESede/CBC/PKCS5Padding 
    今天看到一段3DES加密算法的代码，用的参数是DESede/CBC/PKCS5Padding，感觉比较陌生，于是学习了一下。
    遇到的java代码如下：
    Cipher cipher=Cipher.getInstance("DESede/CBC/PKCS5Padding");
    以前写的代码，给的参数都是DES或DESede。实际上DESede是简写，它与DESede/ECB/PKCS5Padding等价。这个参数分为三段。
    - 第一段是加密算法的名称，如DESede实际上是3-DES。这一段还可以放其它的对称加密算法，如Blowfish等。
    - 第二段是分组加密的模式，除了CBC和ECB之外，还可以是NONE/CFB/QFB等。最常用的就是CBC和ECB了。DES采用分组加密的方式，将明文按8字节（64位）分组分别加密。如果每个组独立处理，则是ECB。CBC的处理方式是先用初始向量IV对第一组加密，再用第一组的密文作为密钥对第二组加密，然后依次完成整个加密操作。如果明文中有两个分组的内容相同，ECB会得到完全一样的密文，但CBC则不会。
    - 第三段是指最后一个分组的填充方式。大部分情况下，明文并非刚好64位的倍数。对于最后一个分组，如果长度小于64位，则需要用数据填充至64位。PKCS5Padding是常用的填充方式填07070707...，如果没有指定，默认的方式就是它。
    补充一点，虽然DES的有效密钥长度是56位，但要求密钥长度是64位（8字节）。3DES则要求24字节。
  有时候java加密的内容用C#解密不了，一般原因都是设定的参数不正确。C#获取的TripleDES对象必需设定Mode和Padding两个属性。Mode和Padding是枚举类型。Mode有对应的ECB和CBC对应的枚举值，但Padding的PKCS5Padding需要对应PKCS7。
   示例代码 
    TripleDES d = TripleDES.Create();
    d.Mode = CipherMode.CBC;
    d.Padding = PaddingMode.PKCS7;
*/

} 