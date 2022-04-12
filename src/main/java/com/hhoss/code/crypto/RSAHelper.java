package com.hhoss.code.crypto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;
import java.util.Arrays;

import javax.crypto.Cipher;

import com.hhoss.code.coder.Base64;
import com.hhoss.jour.Logger;

/**
 * @author kejun
 * @since 2015-8-1
 */
public class RSAHelper {
	private static final Logger logger= Logger.get();
	private String encoding = "UTF-8";
	private String transform = "RSA"; //填充模式，缺省等价于 "RSA/ECB/PKCS1Padding";
	private String algorithm = "MD5withRSA";// 加密算法  or "SHA1withRSA"
	private PublicKey publicKey ;
	private PrivateKey privateKey ;
	
	public RSAHelper(){
		//using default algorithm and encoding;
	}
	
	public RSAHelper(Key key) {
		if(key instanceof PublicKey){
			this.publicKey=(PublicKey)key;
		}else if(key instanceof PrivateKey){
			this.privateKey=(PrivateKey)key;
		}
	}
	public RSAHelper(Key key, String algorithm) {
		this(key);
		this.algorithm=algorithm;
		if(algorithm.startsWith("RSA")){
			//params for encrypt/decrypt;
			this.transform=algorithm;
		}
	}

	public String getAlgorithm() {
		return algorithm;
	}
	
	public RSAHelper setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
		return this;
	}

	public String getEncoding() {
		return encoding;
	}
	
	public RSAHelper setEncoding(String encoding) {
		this.encoding = encoding;
		return this;
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}

	public RSAHelper setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
		return this;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public RSAHelper setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
		return this;
	}

	/**
	 * 
	 * Description:校验数字签名,此方法不会抛出任务异常,成功返回true,失败返回false,要求全部参数不能为空
	 * 
	 * @param dataText
	 *            明文
	 * @param signText
	 *            数字签名base64编码
	 * @return 校验成功返回true 失败返回false
	 */
	public boolean verify(String dataText, String signText) {
		logger.trace("verify sign[{}] for data: {}",signText,dataText);
		boolean veri = false;
		if(dataText!=null&&signText!=null) try {
			byte[] dataBytes = dataText.getBytes(encoding);
			byte[] signBytes = Base64.decodeString(signText);
			veri = verify(dataBytes, signBytes);
		} catch (UnsupportedEncodingException e) {
			logger.warn("数据编码出错",e);
		}
		logger.trace("verify[{}] result: {}",algorithm,veri);
		return veri;
	}

	/**
	 * 验签 signature:加密串参数signature srcData：参数值的拼接串
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public boolean verify(byte[] srcData, byte[] signData) {
		if(srcData==null||signData==null){return false;}
		try {
			Signature sig = Signature.getInstance(algorithm); 
			sig.initVerify(publicKey); // 初始化公钥用于验证的对象
			sig.update(srcData); // 验证数据
			return sig.verify(signData); // 验证传入的签名
		} catch (NoSuchAlgorithmException e) {
			logger.warn("算法有错：{}",algorithm,e);
		} catch (InvalidKeyException e) {
			logger.warn("公钥有错",e);
		} catch (SignatureException e) {
			logger.warn("数据有错",e);
		} catch (Throwable e) {
			logger.warn("验签有错",e);
		}
		return false;
	}
	
	/**
	 * @param text string to be signed
	 * @return
	 */
	public String sign(String text){
		logger.trace("sign for data: {}", text);
		String signText = null;
		if(text!=null)try {
			byte[] dataBytes = text.getBytes(encoding);
			byte[] signed = sign(dataBytes); 
			signText = Base64.encodeBytes(signed);
		} catch (UnsupportedEncodingException e) {
			logger.warn("数据编码出错",e);
		} 
		logger.trace("sign[{}] result: {}", algorithm, signText);
		return signText;
	}

	/**
	 * @param data bytes to be signed
	 * @return
	 */
	public byte[] sign(byte[] data) {
		if(privateKey==null){
			logger.warn("private key is null");
			return null;
		}
		byte[] signData = null;
		if(data!=null)try {
			Signature sig = Signature.getInstance(algorithm); 
			sig.initSign(privateKey);
			sig.update(data);
			signData = sig.sign(); // 对信息的数字签名
		} catch (NoSuchAlgorithmException e) {
			logger.warn("算法出错：{}",algorithm,e);
		} catch (InvalidKeyException e) {
			logger.warn("私钥出错",e);
		} catch (SignatureException e) {
			logger.warn("数据出错",e);
		} catch (Throwable e) {
			logger.warn("签名出错",e);
		}
		return signData;
	}

	  /**
	  * 使用公钥加密数据。
	  * @param data 要加密的数据。
	  * @return 加密后的数据(base64)。
	 * @throws GeneralSecurityException 
	 * @throws Exception 
	  */
	 public String encrypt(String data) throws IOException, GeneralSecurityException  {
		 logger.trace("encrypt for data: {}", data);
		 byte[] srcByte = data.getBytes(encoding);
		 byte[] encByte = encrypt(srcByte);
		 String encText = new String(Base64.encode(encByte),encoding);
		 logger.trace("encrypted result: {}", encText);
		 return encText;
	 }
	  /**
	  * 使用公钥加密数据。
	  * @param data 要加密的数据。
	  * @return 加密后的数据。
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	  */
	 public byte[] encrypt(byte[] data) throws IOException, GeneralSecurityException  {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, publicKey);
        int blockSize = getKeyBitLength(publicKey)/8-11;
        int dlen = data.length;
        try(ByteArrayOutputStream out = new ByteArrayOutputStream()){
	        int offSet = 0;	        
	        while (dlen>offSet) {
	            int nextSize = (dlen-offSet>blockSize)?blockSize:(dlen-offSet);
	            byte[] cache = cipher.doFinal(data, offSet, nextSize);
	            out.write(cache, 0, cache.length);
	            offSet += blockSize;
	        }
        	return out.toByteArray();
        }
	 }
	
	 /**
	  * 使用私钥解密数据。
	  * @param data 要解密的数据(base64)。
	  * @return 解密后数据。
	  */
	 public String decrypt(String data) throws Exception {
		 logger.trace("decrypt for data: {}", data);
		 byte[] encByte = Base64.decodeString(data);
		 byte[] srcByte = decrypt(encByte);
		 String srcText = new String(srcByte,encoding);
		 logger.trace("decrypted result: {}", srcText);		 
		 return srcText;
	 }
	 /**
	  * 使用私钥解密数据。
	  * @param data 要解密的数据。
	  * @return 原数据。
	  */
	 public byte[] decrypt(byte[] data) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, privateKey);
        int blockSize = getKeyBitLength(privateKey)/8;
        int dlen = data.length;
        try(ByteArrayOutputStream out = new ByteArrayOutputStream()){
	        int offSet = 0;	        
	        while (dlen>offSet) {
	            int nextSize = (dlen-offSet>blockSize)?blockSize:(dlen-offSet);
	            byte[] cache = cipher.doFinal(data, offSet, nextSize);
	            out.write(cache, 0, cache.length);
	            //out.write(cache, 11, cache.length);//if nopadding
	            offSet += blockSize;
	        }
        	return out.toByteArray();
        }
	 }
	 
	 public static int getKeyBitLength(Key key)  {
	    if(key instanceof RSAKey){
	   		return ((RSAKey)key).getModulus().bitLength();
	   	}
		throw new SecurityException("Can't get Key Algorithm length.");
	}
	 
	 private Cipher getCipher(int mode, Key key) throws GeneralSecurityException{
	    // Cipher.getInstance(algorithm, DEFAULT_PROVIDER);
		// Cipher.getInstance("RSA","BC");//, new BouncyCastleProvider()); 
		// Cipher.getInstance("RSA"); //default same with "RSA/ECB/PKCS1Padding";
		Cipher cipher = Cipher.getInstance(transform);
        cipher.init(mode, key);
        return cipher;
	 }


	
	public static void main(String[] args) {
		try {
			// getPrivateKey("certs/signature.p12","pwd");
			//SignatureHelper.testGenerateKeyPair();
			//SignatureHelper.testGenerateKeys();
			
			byte[] bytes1= Base64.decodeString("ctohL7mNa8Ksgt14SCKf8VRJ7793XvOT5JgN/Jit0YB/G+kLBi3GVcED+6c4wBxfu4FcpPPFN4iX\neNYoPRR7ddc/SyYYbio+M8PCpc+Ik8qnkFSNCCVUYth+/A0/m5cSRbt7O/gb++txVPSUtCC7u89O\nuRbKlWILMK7dZSlMDdEEzD8+r/YNT5AoCMFo5+N8SYtpD2+cfdIqNzXecPrCefhYFBC7sZfMiwcT\nNKnvArPIwrsQA5TyqlcynoZxiyRa3h1G2OZpip54p/NxbAzsGdVLwHJ8aZcZu4PbBE3Hy/vHc53J\ngc5B9Om7oH1WUrHBuJf3K9fgUH+qQA9ZCvNZTA==\n");
			byte[] bytes2= Base64.decodeString("ctohL7mNa8Ksgt14SCKf8VRJ7793XvOT5JgN/Jit0YB/G+kLBi3GVcED+6c4wBxfu4FcpPPFN4iXeNYoPRR7ddc/SyYYbio+M8PCpc+Ik8qnkFSNCCVUYth+/A0/m5cSRbt7O/gb++txVPSUtCC7u89OuRbKlWILMK7dZSlMDdEEzD8+r/YNT5AoCMFo5+N8SYtpD2+cfdIqNzXecPrCefhYFBC7sZfMiwcTNKnvArPIwrsQA5TyqlcynoZxiyRa3h1G2OZpip54p/NxbAzsGdVLwHJ8aZcZu4PbBE3Hy/vHc53Jgc5B9Om7oH1WUrHBuJf3K9fgUH+qQA9ZCvNZTA==");
			logger.debug("length:{};equal:{}",bytes1.length,Arrays.equals(bytes1,bytes2));
			String srcData = "37078219930102201710004000805admin21371124818520150802-131523";
			
			//RSAHelper signHelper = new RSAHelper(new File("S:/work/dev/openssl/_cedit2go/certs/signature.crt")); 
			//signHelper.setPublicCertFile("S:/work/dev/openssl/_cedit2go/certs/signature.crt");
			//signHelper.setPrivatePKCS12File("file:///S:/work/dev/openssl/_cedit2go/certs/signature.p12", "credit2go");
			RSAKeyUtil ru = new RSAKeyUtil(new File("/certs/credit2go.p12"),"credit2go"); 
			System.out.println("内容: " + srcData);
			
			RSAHelper signHelper = new RSAHelper(ru.getPrivateKey()); 
			String signText = signHelper.sign(srcData);
			System.out.println("签名: " + signText);
			
			signHelper = new RSAHelper(ru.getPublicKey()); 
			boolean v = signHelper.verify(srcData, signText);
			System.out.println("验签: "+v);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
