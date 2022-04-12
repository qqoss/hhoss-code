package com.hhoss.code.crypto;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author kejun
 * @deprecated replaced by com.hhoss.code.crypto.AESCoder
 */
public class AesUtil{

    //FILES[0]：明文文件路径、FILES[1]：加密文件路径、FILES[2]：解密文件路径
    static final String[] FILEPATHS={"D:/fileForP2P/out/3005-ZL-Z01-FINTRAN-000002-20170328","C:/Users/wangfan/Desktop/3005-ZL-Z01-FINTRAN-000002-20170328","D:/DEMO/content_decrypt"};
    static final String KEYPATH="MIIEvgIBADANBgkqhkiG9w";
    public static final String aes_key_algorithm = "AES";
    public static final String cipher_algorithm = "AES/ECB/PKCS5Padding";
    /**
     * 文件加解密测试
     * */
    public static void main(String[] args) throws Exception {
       
        String privateKey = KEYPATH;
        encryptHand(new File(FILEPATHS[0]),new File(FILEPATHS[1]),privateKey);//加密处理

        decryptHand(new File(FILEPATHS[1]), new File(FILEPATHS[2]), privateKey);//解密处理
        
    }


    /**
     * 获取密钥
     * @param filePath
     * @return
     * @throws IOException
     */
    public static String getPrivateKey(String privateKeyPath) throws IOException{
    	 File fi = new File(privateKeyPath);
         FileReader fre = new FileReader(fi);
         BufferedReader bre = new BufferedReader(fre);
         String privateKey = bre.readLine();
         bre.close();
         return  privateKey;
    }
    
    /**
     *  初始化密钥
     *
     *  @param keyPath  密码
     *
     *  @return  key
     * */
    public static SecretKey getKey(String keyPath) {
        try {
            KeyGenerator _generator = KeyGenerator.getInstance( aes_key_algorithm );
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG" );
            secureRandom.setSeed(keyPath.getBytes());
            _generator.init(128,secureRandom);
            return _generator.generateKey();
        }  catch (Exception e) {
            throw new RuntimeException( "初始化密钥出现异常 " );
        }
    }

    /**
     * 加密
     *
     * @param content  明文
     * @param keyPath  加密密钥
     * @return
     */
    public static byte[] encrypt(String content, String keyPath) throws Exception {

        SecretKeySpec key = null;
        SecretKey secretKey =getKey(keyPath);
        byte[] enCodeFormat = secretKey.getEncoded();
        key = new SecretKeySpec(enCodeFormat, aes_key_algorithm);
        Cipher cipher = Cipher.getInstance(cipher_algorithm);// 创建密码器
        byte[] byteContent = content.getBytes("GBK");
        cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
        byte[] result = null;
        result = cipher.doFinal(byteContent);
        return result;
    }

    /**解密
     * @param content 密文
     * @param keyPath 解密密钥
     * @return
     */
	public static byte[] decrypt(byte[] content, String keyPath) throws Exception {

        SecretKeySpec key = null;
        byte[] result = null;
        SecretKey secretKey =getKey(keyPath);
        byte[] enCodeFormat = secretKey.getEncoded();
        key = new SecretKeySpec(enCodeFormat, aes_key_algorithm);
        Cipher cipher = Cipher.getInstance(cipher_algorithm);// 创建密码器
        cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
        result = cipher.doFinal(content);
        return result;
    }

    /**将二进制转换成16进制
     * @param buf
     * @return
     */
    public static String parseByte2HexStr(byte buf[]) throws Exception {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    /**将16进制转换为二进制
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) throws Exception{
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length()/2];
        for (int i = 0;i< hexStr.length()/2; i++) {
            int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);
            int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    /**
     * 加密,读取旧文件内容加密后写入新文件
     * @param file1 明文文件
     * @param file2 加密文件
     * @param keyPath	密钥路径
     * @return	result
     */
    public static String encryptHand(File file1,File file2, String keyPath) throws Exception{
        String result="";
        String line = "";
        byte[] bt;
        String encryptResultStr="";
        BufferedReader br = new BufferedReader (new InputStreamReader(new FileInputStream(file1),"GBK"));
        BufferedWriter bw = new BufferedWriter (new OutputStreamWriter(new FileOutputStream(file2), "GBK"));
        System.out.println("/*********************--encrypt start--*********************/");
        try{
            while((line=br.readLine())!=null){
                 bt=encrypt(result + line, keyPath);//逐行加密
                 encryptResultStr =parseByte2HexStr(bt);
                 bw.write(encryptResultStr);
                 bw.newLine();
             }
             bw.flush();
             System.out.println("/*********************--encrypt end--*********************/");
             return result;
         }finally {
             bw.close();
             br.close();
         }
    }


    /**
     * 解密,读取旧加密文件内容解密后写入新文件
     * @param file1 加密文件
     * @param file2 明文文件
     * @param keyPath 密钥路径
     */
    public static void decryptHand(File file1,File file2,String keyPath) throws Exception{
        String line ="";
        byte[] decryptFrom=null;
        byte[] decryptResult=null;
        
        BufferedReader br = new BufferedReader (new InputStreamReader (new FileInputStream(file1),"GBK"));
        BufferedWriter bw = new BufferedWriter (new OutputStreamWriter (new FileOutputStream(file2),"GBK"));
        System.out.println("/*********************--decrypt start--*********************/");
        try {
            while((line = br.readLine())!=null){
                //解密
                String result="";
                decryptFrom =parseHexStr2Byte(result+line);
                decryptResult = decrypt(decryptFrom, keyPath);//逐行解密
                result=new String(decryptResult,"GBK");
                bw.write(result);
                bw.newLine();
            }
            bw.flush();
            System.out.println("/*********************--decrypt end--*********************/");
        }finally {
            bw.close();
            br.close();
        }
    }
}
