package com.hhoss.code.pgp;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.encoders.Base64;

public class PGPExampleUtil {
	
	static{ if( Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)==null ) {
				Security.addProvider(new BouncyCastleProvider());
	}}

	
	static byte[] compressFile(String fileName, int algorithm) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
		PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
		comData.close();
		return bOut.toByteArray();
	}

	/**
	 * Search a secret key ring collection for a secret key corresponding to keyID
	 * if it exists.
	 *
	 * @param pgpSec a secret key ring collection.
	 * @param keyID  keyID we want.
	 * @param pass   passphrase to decrypt secret key with.
	 * @return the private key.
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException, NoSuchProviderException {
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
		if (pgpSecKey == null) {
			return null;
		}
		return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
	}

	static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
		InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
		PGPPublicKey pubKey = readPublicKey(keyIn);
		keyIn.close();
		return pubKey;
	}

	/**
	 * A simple routine that opens a key ring file and loads the first available key
	 * suitable for encryption.
	 *
	 * @param input data stream containing the public key data
	 * @return the first public key found.
	 * @throws IOException
	 * @throws PGPException
	 */
	static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
//
// we just loop through the collection till we find a key suitable for encryption, in the real
// world you would probably want to be a bit smarter about this.
//
		Iterator keyRingIter = pgpPub.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
			Iterator keyIter = keyRing.getPublicKeys();
			while (keyIter.hasNext()) {
				PGPPublicKey key = (PGPPublicKey) keyIter.next();
				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}
		throw new IllegalArgumentException("Can't find encryption key in key ring.");
	}

	static PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException {
		InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
		PGPSecretKey secKey = readSecretKey(keyIn);
		keyIn.close();
		return secKey;
	}

	/**
	 * A simple routine that opens a key ring file and loads the first available key
	 * suitable for signature generation.
	 *
	 * @param input stream to read the secret key ring collection from.
	 * @return a secret key.
	 * @throws IOException  on a problem with using the input stream.
	 * @throws PGPException if there is an issue parsing the input stream.
	 */
	static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
//
// we just loop through the collection till we find a key suitable for encryption, in the real
// world you would probably want to be a bit smarter about this.
//
		Iterator keyRingIter = pgpSec.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
			Iterator keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = (PGPSecretKey) keyIter.next();
				if (key.isSigningKey()) {
					return key;
				}
			}
		}
		throw new IllegalArgumentException("Can't find signing key in key ring.");
	}

	/**
	 * 私有方法，用于生成指定位宽的PGP RSA密钥对
	 *
	 * @param rsaWidth_ RSA密钥位宽
	 * @return 未经私钥加密的PGP密钥对
	 * @throws Exception IO错误，数值错误等
	 */
	private static PGPKeyPair generateKeyPair(int rsaWidth_) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");// 获取密钥对生成器实例
		kpg.initialize(rsaWidth_);// 设定RSA位宽
		KeyPair kp = kpg.generateKeyPair();// 生成RSA密钥对
		return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, new Date());// 返回根据日期，密钥对生成的PGP密钥对
	}

	/**
	 * 获取PGP密钥<br>
	 * 密钥是将密钥对的私钥部分用对称的加密方法CAST-128算法加密，再加上公钥部分
	 *
	 * @param identity_   密钥ID也就是key值，可以用来标记密钥属于谁
	 * @param passPhrase_ 密钥的密码，用来解出私钥
	 * @param rsaWidth_   RSA位宽
	 * @return PGP密钥
	 * @throws Exception IO错误和数值错误等
	 */
	public static PGPSecretKey getSecretKey(String identity_, String passPhrase_, int rsaWidth_) throws Exception {
		char[] passPhrase = passPhrase_.toCharArray(); // 将passPharse转换成字符数组
		PGPKeyPair keyPair = generateKeyPair(rsaWidth_); // 生成RSA密钥对
		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1); // 使用SHA1作为证书的散列算法
		/**
		 * 用证书等级生成的认证，将公私钥对和PGP ID密码绑定构造PGP密钥（SecretKey）
		 *
		 * @param certificationLevel         PGP密钥的证书等级
		 * @param keyPair                    需要绑定的公私钥对
		 * @param id                         需要绑定的ID
		 * @param checksumCalculator         散列值计算器，用于计算私钥密码散列
		 * @param hashedPcks                 the hashed packets to be added to the
		 *                                   certification.（先不管）
		 * @param unhashedPcks               the unhashed packets to be added to the
		 *                                   certification.（也先不管）
		 * @param certificationSignerBuilder PGP证书的生成器
		 * @param keyEncryptor               如果需要加密私钥，需要在这里传入私钥加密器
		 * @throws PGPException 一些PGP错误
		 */
		return new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity_, sha1Calc, null, null,
				new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				// 密钥的加密方式
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));
	}

	@SuppressWarnings("restriction")
	public static void main(String[] args) throws Exception {
		String passPhrase_ = "123456789";
		char[] passPhrase = passPhrase_.toCharArray(); // 将passPharse转换成字符数组

		PGPSecretKey secretKey = getSecretKey("wathdata", passPhrase_, 2048);

		// 这里打印私钥-------------重要
		String privateKeyString = Base64.toBase64String(secretKey.getEncoded());
		System.out.println(privateKeyString);

		PGPPublicKey publicKey = secretKey.getPublicKey();
		// FileOutputStream fileOutputStream = new FileOutputStream("c://1.txt");
		byte[] encoded = publicKey.getEncoded();
		// 这里打印公钥----------------重要
		String publicKeyString = Base64.toBase64String(encoded);
		System.out.println(publicKeyString);

	}

}