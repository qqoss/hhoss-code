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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.hhoss.jour.Logger;
import com.hhoss.util.HMap;

public class AESCoder {
	public static final Logger logger= Logger.get();
	public static final String aes_key_algorithm = "AES";
	public static final String cipher_algorithm = "AES/ECB/PKCS5Padding";

	/**
	 * 文件加解密测试
	 * */
	public static void main(String[] args) throws Exception {
		HMap<String>  params = getParams(args);		
		if("encrypt".equalsIgnoreCase(params.get("action"))){
			encryptHand(new File(params.get("origin")), new File(params.get("target")), getKey(params.get("aesKey")));
		}else if("decrypt".equalsIgnoreCase(params.get("action"))){
			decryptHand(new File(params.get("origin")), new File(params.get("target")), getKey(params.get("aesKey")));
		}else{
			logger.info("usage: <encrypt|decrypt> <aesKeyFile|keyString> <originFile> <targetFile>");
		}
	}
	
	private HMap<String> testParams(){
		return new HMap<String>().let("action", "encrypt","origin", "origin.txt", "target", "target.txt", "aesKey","MIIEvgIBADANBgkqhkiG9w");
	}
	
	private static HMap<String> getParams(String[] args){
		HMap<String> map = new HMap<>();
		if(args!=null && args.length>3){
			map.let("action",args[0]);
			map.let("origin",args[2],"target",args[3]);
			map.let("aesKey",args[1].startsWith("MII")?args[1]:getPrivateKey(args[1]));
		}
		return map;
	}

	/**
	 * 
	 * @param keys file path
	 * @return keys String
	 * @throws IOException
	 */
	public static String getPrivateKey(String aesKeyFile) {
		String aesKey=null;
		File f = new File(aesKeyFile);
		try(BufferedReader bre = new BufferedReader(new FileReader(f))){;
			aesKey = bre.readLine();
		} catch (IOException e) {
			logger.warn("get AES keys error from file: [{}].",aesKeyFile);
		}
		return aesKey;
	}

	/**
	 * @param string keys
	 * @return SecretKey
	 * @throws NoSuchAlgorithmException 
	 * */
	public static SecretKey getKey(String keyStr) throws NoSuchAlgorithmException {
			KeyGenerator generator = KeyGenerator.getInstance(aes_key_algorithm);
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			secureRandom.setSeed(keyStr.getBytes());
			generator.init(128, secureRandom);
			return generator.generateKey();
	}
	
	public static SecretKey getKey(File keyFile) throws NoSuchAlgorithmException, IOException{
	    StringBuilder keyEncode = new StringBuilder();
		try(BufferedReader br = new BufferedReader(new FileReader(keyFile))){
		    String line;
		    while((line=br.readLine())!=null){
		    	if(line.charAt(0)== '-'||line.charAt(0) == '#'){
		    		continue;
		    	}
		    	keyEncode.append(line);// without "\r\n";
		    }
		}
	    return getKey(keyEncode.toString());
	}

	/**
	 * 
	 * @param content   明文
	 * @param keyStr   加密密钥
	 * @return
	 */
	public static byte[] encrypt(String content, String keyStr) throws Exception {
		/*
		SecretKey secretKey = getKey(keyStr);
		SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), aes_key_algorithm);
		*/		
		return encrypt(content,getKey(keyStr));
	}
	
	public static byte[] encrypt(String content, Key key) throws Exception {
		Cipher cipher = Cipher.getInstance(cipher_algorithm);// 创建密码器
		byte[] byteContent = content.getBytes("GBK");
		cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
		byte[] result = null;
		result = cipher.doFinal(byteContent);
		return result;

	}

	/**
	 * 解密
	 * 
	 * @param content
	 *            密文
	 * @param keyPath
	 *            解密密钥
	 * @return
	 */
	public static byte[] decrypt(byte[] content, String keyStr) throws Exception {
		/*
		SecretKey secretKey = getKey(keyStr);
		SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), aes_key_algorithm);
		*/		
		return decrypt(content,getKey(keyStr));
	}
	
	public static byte[] decrypt(byte[] content, Key key) throws Exception {
		Cipher cipher = Cipher.getInstance(cipher_algorithm);// 创建密码器
		cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
		return cipher.doFinal(content);
	}

	/**
	 * 将二进制转换成16进制
	 * 
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

	/**
	 * 将16进制转换为二进制
	 * 
	 * @param hexStr
	 * @return
	 */
	public static byte[] parseHexStr2Byte(String hexStr) throws Exception {
		if (hexStr.length() < 1)
			return null;
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) {
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}

	/**
	 * 加密,读取旧文件内容加密后写入新文件
	 * 
	 * @param file1
	 *            明文文件
	 * @param file2
	 *            加密文件
	 * @param keyStr
	 *            密钥
	 * @return result
	 */
	public static String encryptHand(File file1, File file2, Key key) throws Exception {
		String line = "";
		byte[] bt;
		String encryptResultStr = "";
		BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file1), "GBK"));
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file2), "GBK"));
		logger.debug("encrypt source file: {}",file1);
		try {
			while ((line = br.readLine()) != null) {
				bt = encrypt(line, key);// 逐行加密
				encryptResultStr = parseByte2HexStr(bt);
				bw.write(encryptResultStr);
				bw.newLine();
			}
			bw.flush();
		} finally {
			bw.close();
			br.close();
			logger.debug("encrypt target file: {}",file2);
		}
		return line;
	}

	/**
	 * 解密,读取旧加密文件内容解密后写入新文件
	 * 
	 * @param file1
	 *            加密文件
	 * @param file2
	 *            明文文件
	 * @param key
	 *            密钥
	 */
	public static String decryptHand(File file1, File file2, Key key) throws Exception {
		String line = "";
		byte[] decryptFrom = null;
		byte[] decryptResult = null;

		BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file1), "GBK"));
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file2), "GBK"));
		logger.debug("decrypt source file: {}",file1);
		try {
			while ((line = br.readLine()) != null) {
				decryptFrom = parseHexStr2Byte(line);
				decryptResult = decrypt(decryptFrom, key);// 逐行解密
				bw.write(new String(decryptResult, "GBK"));
				bw.newLine();
			}
			bw.flush();
		} finally {
			bw.close();
			br.close();
			logger.debug("decrypt to target file: {}",file1);
		}
		return line;
	}

}
