package com.hhoss.code.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.crypto.Cipher;

import com.hhoss.code.HexCoder;
import com.hhoss.code.coder.Base64;

/**
 * @author kejun
 * @since 2015-8-1
 */
public class SignatureProvider {
	private static final String encoding = "UTF-8";
	private static final String algorithm = "MD5withRSA";// 加密算法  or "SHA1withRSA"

	private SignatureProvider() {}

	/**
	 * @param p12Path the pcks12 keystore file path
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static PrivateKey getPrivateKey(String filePath, String pwd) throws GeneralSecurityException, IOException {
		InputStream is = SignatureProvider.class.getClassLoader().getResourceAsStream(filePath);
		return getPrivateKey(is, pwd);
	}
	
	/**
	 * @param PKCS12 keystore inutstream 
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static PrivateKey getPrivateKey(InputStream is, String pwd) throws GeneralSecurityException, IOException {
		KeyStore ks = KeyStore.getInstance("PKCS12");

		char[] keyPWD = pwd.toCharArray();
		ks.load(is,  keyPWD);
		is.close();

		//System.out.println("keystore type = " + ks.getType());
		Enumeration enuml = ks.aliases();
		String keyAlias = null;
		if (enuml.hasMoreElements()) {
			keyAlias = (String) enuml.nextElement();
			//System.out.println("alias=[" + keyAlias + "]");
		}
		//System.out.println("is key entry = " + ks.isKeyEntry(keyAlias));
		PrivateKey prikey = (PrivateKey) ks.getKey(keyAlias, keyPWD);
		
		Certificate cert = ks.getCertificate(keyAlias);
		PublicKey pubkey = cert.getPublicKey();
		return prikey;
	}

	/**
	 * @param keyBytes PKCS8Encoded key bytes
	 * @return
	 */
	public static PrivateKey getPrivateKey(byte[] keyBytes) {
		try {			
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			return privateKey;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("初始化加密算法时报错");
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println("初始化私钥时报错");
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 获取公钥 publickey:公钥地址
	 * @param certPath
	 * @return
	 */
	public static PublicKey getPublicKey(String certPath) {
		try{
			 FileInputStream fis=new FileInputStream(certPath);
			 return getPublicKey(fis);
		}catch(Exception e){
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param certStream
	 * @return
	 */
	public static PublicKey getPublicKey(InputStream certStream) {
		try {
			// 开始获取公钥
			if (certStream != null) {
				// 通过加密算法获取公钥
				Certificate cert = null;
				try {
					CertificateFactory cf = CertificateFactory.getInstance("X.509"); // 指定证书类型
					cert = cf.generateCertificate(certStream); // 获取证书
					return cert.getPublicKey(); // 获得公钥
				} finally {
					if (certStream != null) {
						certStream.close();
					}
				}
			}
		} catch (IOException e) {
			System.out.println("无法获取url连接");
			e.printStackTrace();
		} catch (CertificateException e) {
			System.out.println("获取证书失败");
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * @param keyBytes
	 * @return
	 */
	public static PublicKey getPublicKey(byte[] keyBytes) {
		try {			
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("初始化加密算法时报错");
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println("初始化公钥时报错");
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 从公钥数据取得公钥
	 * 
	 * @param keyBytes only keyBytes, no header
	 * @return
	 */
	public static PublicKey getPublicKey1(byte[] keyBytes) {
		PublicKey rsaPubKey = null;
		byte[] bX509PubKeyHeader = { 48, -127, -97, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -127, -115, 0 };
		byte[] bPubKey = new byte[keyBytes.length + bX509PubKeyHeader.length];
		System.arraycopy(bX509PubKeyHeader, 0, bPubKey, 0, bX509PubKeyHeader.length);
		System.arraycopy(keyBytes, 0, bPubKey, bX509PubKeyHeader.length, keyBytes.length);
	
		return	getPublicKey(keyBytes);
	}
	
	//please ensure map.remove("sign") is invoked first;
	public static String getValuesByKeySorted(Map<String,Object> map){
		Map<String,Object> sortedMap = map;
		if(!(map instanceof TreeMap)){
			sortedMap = new TreeMap<>();
			sortedMap.putAll(map);
		}
		StringBuilder sb = new StringBuilder();
		for(Entry<String,Object> ent:sortedMap.entrySet()){
			sb.append(ent.getValue()==null?"":ent.getValue().toString());
		}
		return sb.toString();
	}

	/**
	 * 
	 * Description:校验数字签名,此方法不会抛出任务异常,成功返回true,失败返回false,要求全部参数不能为空
	 * 
	 * @param pubKeyText 
	 *            公钥,base64编码
	 * @param dataText
	 *            明文
	 * @param signTest
	 *            数字签名的密文,base64编码
	 * @return 校验成功返回true 失败返回false
	 */
	public static boolean verify(String pubKeyText, String dataText, String signText) {
		try {
			byte[] pubKeyBytes = Base64.decodeString(pubKeyText);
			byte[] signBytes = Base64.decodeString(signText);
			byte[] dataBytes = dataText.getBytes(encoding);
			PublicKey pubKey = getPublicKey(pubKeyBytes);
			return verify(pubKey, dataBytes, signBytes);

		} catch (UnsupportedEncodingException e) {
			System.out.println("编码错误");
			e.printStackTrace();
		}
		// 取公钥匙对象
		return false;
	}

	/**
	 * 验签 signature:加密串参数signature srcData：参数值的拼接串
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public static boolean verify(PublicKey publicKey, byte[] srcData, byte[] signData) {

		try {
			Signature sig = Signature.getInstance(algorithm); 
			sig.initVerify(publicKey); // 初始化公钥用于验证的对象
			sig.update(srcData); // 验证数据
			return sig.verify(signData); // 验证传入的签名
			// } catch (UnsupportedEncodingException e) {
			// System.out.println("编码错误");
			// e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("初始化加密算法时报错");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("初始化公钥时报错");
			e.printStackTrace();
		} catch (SignatureException e) {
			System.out.println("验证数据时报错");
			e.printStackTrace();
		} catch (Throwable e) {
			System.out.println("校验签名失败");
			e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * @param privateKeyText 私钥 Base64 text
	 * @param dataText 数据
	 * @return
	 */
	public static String sign(String privateKeyText, String dataText){
		try {
			byte[] privateBytes = Base64.decodeString(privateKeyText);
			byte[] dataBytes = dataText.getBytes(encoding);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
			KeyFactory keyGen = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyGen.generatePrivate(keySpec);
			byte[] signed = sign(privateKey,dataBytes); 
			return Base64.encodeBytes(signed);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | UnsupportedEncodingException e) {
			System.out.println("初始化加密算法时报错");
			e.printStackTrace();
		} catch (Throwable e) {
			System.out.println("签名失败");
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param privateKey 私钥 
	 * @param srcData 数据
	 * @return
	 */
	public static byte[] sign(PrivateKey privateKey, byte[] srcData) {
		try {
			Signature sig = Signature.getInstance(algorithm); 
			sig.initSign(privateKey);
			sig.update(srcData);
			byte[] signed = sig.sign(); // 对信息的数字签名
			return signed; 
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			System.out.println("初始化加密算法时报错");
			e.printStackTrace();
		} catch (Throwable e) {
			System.out.println("校验签名失败");
			e.printStackTrace();
		}
		return null;
	}	
	
	   /**
     * 使用指定的公钥加密数据。
     * 
     * @param publicKey 给定的公钥。
     * @param data 要加密的数据。
     * @return 加密后的数据。
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {
        //Cipher cipher = Cipher.getInstance(algorithm, DEFAULT_PROVIDER);
   	    Cipher cipher= Cipher.getInstance("RSA");//, new BouncyCastleProvider()); 
   	    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
 
    /**
     * 使用指定的私钥解密数据。
     * 
     * @param privateKey 给定的私钥。
     * @param data 要解密的数据。
     * @return 原数据。
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception {
        //Cipher cipher = Cipher.getInstance(algorithm, DEFAULT_PROVIDER);
   	    Cipher cipher= Cipher.getInstance("RSA");//, new BouncyCastleProvider()); 
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
 
	
	///////////////////////test method//////////////////////
	public static void testGenKeys() {
		try {
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
			keygen.initialize(1024,  new SecureRandom("credit2go".getBytes()));
			KeyPair keys = keygen.genKeyPair();
			PublicKey pubkey = keys.getPublic();
			PrivateKey prikey = keys.getPrivate();

			System.out.println("pubKey.Hex=" + HexCoder.toHex(pubkey.getEncoded()));
			System.out.println("priKey.Hex=" + HexCoder.toHex(prikey.getEncoded()));
			System.out.println("pubKey.Base64=" + Base64.encodeBytes(pubkey.getEncoded()));
			System.out.println("priKey.Base64=" + Base64.encodeBytes(prikey.getEncoded()));
		} catch (java.lang.Exception e) {
			e.printStackTrace();
			System.out.println("生成密钥对失败");
		}

	}

	public static void testSign() {
		try {
			//byte[] keyBytes	= Base64.decodeBase64("MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMZHVO+/k5TBS6ieROCpvM3nf7jCoHmav6TqYwUqpQnsa7S3ba6scEMLbvPIBHAx/jlX8JGhG+YkJCLZV+e0S4qSECJIOMHPcBS4etymdJXR36IYVJDYhxtZWEjYyhS5YKIYWhFZuxBrlxSPO25cl9qS9E5wtg2FdOcaUKrzcsWZAgMBAAECgYEAsTKEdLJoKPPKMsom0gS/Z+Bwo2TEV4j1pmOV1MM0tTalVt7q1cTjmvc31AO3+7Ch+wtdQjiSH03DQaWtSrQ1IPINOpl22wiA5pS1iHSOJQtCIxqvAwoEs78E5D1/0TUs8O4P1SfZbpMabb0pLgFhtBQWGwvJN6zETSH/jUa1pNUCQQDjCikIh06qGA4Ws2l2H760n5FTzVXZhDMFZSqVEFsJa3ocumbdcQVPFE3eLBv3ysMv15MJ5JbtlpctSf0slrOHAkEA35H/UkNf+lR58nPZ5Wgu7tE3siFsou9RcNxIj2c5w4wj4gqyD8q3g+wZLUtvLZomlfMTn+a0MUz4luB0OC9F3wJALbflDWeZypyvcZjNOtEnqN2c+SAXEocRcxutGHlDq8DtxQ0wG5VfuU3gZEXDmAFHjsG9RTe3wL4bUS5eAfWSzwJBAJP7PCfERtwYXFt6CWlKa35R5261pwW2KI7uj+yzo81mjj3JXJENWiks9oE/pAhoN1AbhArcFrtnOkgLq4Gg8LsCQEKy7soJ4tcYvWED8uKq8x5fPoPHPk2OdJ3G+OVhKx1/yyfUFLjkTeN3+YHAmg89fyb4Yj/lQjPOoUJvonjIp4M=");
			//PrivateKey privateKey = getPrivateKey(keyBytes);
			String fs2 ="S:/work/scm/caizhong/trunk/credit2go-core/src/test/resources/certs/fdepCust_pkcs.pem";
			PrivateKey privateKey = RSAKeyUtil.getPrivateKey(fs2);
			String srcData = "34088119910119285910004000805admin21371124818520150802-131523";
			byte[] signed = sign(privateKey, srcData.getBytes(encoding)); 

			System.out.println("内容: " + srcData);
			System.out.println("签名: " + Base64.encodeBytes(signed));
		} catch (java.lang.Exception e) {
			e.printStackTrace();
			System.out.println("签名失败");
		}
	}

	public static void testVerify() {
		try {
			//byte[] signed   = Hex.decodeHex("81c5919ce117372edd7d0559030d866bd587a497bcb6a6d80b928e784bf386a4a9c1ab80fbbcf5040e57fdff8be176df4b7bb15013dfd3a8bb32d23b3259f162e1d89798ad0977377d931e903942869e078e1ed5b8826d72bb01b78bd94836e2cb1eb239743c0fb8d8f4ed1b14a3c11f1a86ff5682a1fb83f59a38c5ac9d67c8".toCharArray());
			//byte[] keyBytes = Hex.decodeHex("30819f300d06092a864886f70d010101050003818d0030818902818100886a4ba7ad410db5e579244afefa34dbd42dbfa0aa9d9d7079940b95d1b4e8f8f2d598c45ace42fb5ccc15941300d4723f22acc90c222ae5631fe9a4c7e5a6d8cc5333da22404a4fd2ba0dd58e1e77be12b590077e6ac3ee30658619669760036b7721ad6229289b13a6801dfcf55fefa20b43fbdbbfbc3034a15bf9dc8b970f0203010001".toCharArray());
			//byte[] keyBytes = Base64.decodeBase64("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGR1Tvv5OUwUuonkTgqbzN53+4wqB5mr+k6mMFKqUJ7Gu0t22urHBDC27zyARwMf45V/CRoRvmJCQi2VfntEuKkhAiSDjBz3AUuHrcpnSV0d+iGFSQ2IcbWVhI2MoUuWCiGFoRWbsQa5cUjztuXJfakvROcLYNhXTnGlCq83LFmQIDAQAB");
//			PublicKey publicKey = getPublicKey(keyBytes);
			String path = "S:/work/scm/caizhong/trunk/credit2go-core/src/test/resources/certs/fdepCust.crt";
			PublicKey publicKey = getPublicKey(path);
			//System.out.println("PublicKey: " + new String(Hex.encodeHex(keyBytes)));

			String srcData = "34088119910119285910004000805admin21371124818520150802-131523";
			byte[] signed = Base64.decodeString("2wA+alyfygU1p/SfQtnttDGPEelUgZQjawcx6Ir8ZmEQ/fnZwsMnsQ3kluAV8cPQVp+waY4vYGcJQYHuNiZa+FnRnF/VGHuuHp++dwlbFZxJPQEhICLzVIAxHoQgdUF8fPwkddBb5JZp28NL1JTDULfreRNBcEPCsRBdc0WqTHI=");
			boolean v = verify(publicKey, srcData.getBytes(encoding), signed);
			if (v) {
				System.out.println("内容: " + srcData);
				System.out.println("验签成功");
			} else {
				System.out.println("验签失败");
			}

		} catch (java.lang.Exception e) {
			e.printStackTrace();
		}
	}
	
	private  static void test2() throws Exception{
		String dataText = "{\"merNo\":\"000075\",\"orderId\":\"201701191704362301\"}00000000success";
		String signText = "p6XqJJd5vSGBlf/ENMPxZ3lxMSf/VYhyhjlaGhFjJb5Npy+lBo+vWheuIoCEQlzMOUibXTPZG6dwwY+Ax/meQR8pHkmCFgplrI+cMBa8j0ijRuslhJx0SIqkamzxSXywWggFo+6mWl2LtIEidJXiWolsIQxzKfZyUWeOBRKg5lUyOSxqsQonjpoy7Uh3MPdOCvUHJnQTky5hyQMjI5VfSKZ3AOnwqJ3nRrIEm9EeAXjq7m7mCRjY09cn1SGsRimF5a6+FU0e1W5iNyO4XKeYlYM9gF5J7Th3uHTM/vIVawFrvChoSgV3sYZJboT9hliBy+x4kgAgVFNHwUhOGy2t4w==";
		PublicKey key = new RSAKeyUtil(new File("S:/cs_jx.crt")).getPublicKey();
		boolean v =new RSAHelper(key).setAlgorithm("SHA1WithRSA").verify(dataText, signText);
		//boolean v = verify(key, dataText.getBytes(encoding), signText.getBytes());
		if (v) {
			System.out.println("验签成功");
		} else {
			System.out.println("验签失败");
		}
	}	
	
	public static void main(String[] args) {
		try {
			// getPrivateKey("certs/signature.p12");
			//testGenKeys();
			testSign();
			testVerify();
			test2();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
