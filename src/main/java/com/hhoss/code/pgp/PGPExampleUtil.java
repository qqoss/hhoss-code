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
	 * ??????????????????????????????????????????PGP RSA?????????
	 *
	 * @param rsaWidth_ RSA????????????
	 * @return ?????????????????????PGP?????????
	 * @throws Exception IO????????????????????????
	 */
	private static PGPKeyPair generateKeyPair(int rsaWidth_) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");// ??????????????????????????????
		kpg.initialize(rsaWidth_);// ??????RSA??????
		KeyPair kp = kpg.generateKeyPair();// ??????RSA?????????
		return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, new Date());// ???????????????????????????????????????PGP?????????
	}

	/**
	 * ??????PGP??????<br>
	 * ????????????????????????????????????????????????????????????CAST-128????????????????????????????????????
	 *
	 * @param identity_   ??????ID?????????key???????????????????????????????????????
	 * @param passPhrase_ ????????????????????????????????????
	 * @param rsaWidth_   RSA??????
	 * @return PGP??????
	 * @throws Exception IO????????????????????????
	 */
	public static PGPSecretKey getSecretKey(String identity_, String passPhrase_, int rsaWidth_) throws Exception {
		char[] passPhrase = passPhrase_.toCharArray(); // ???passPharse?????????????????????
		PGPKeyPair keyPair = generateKeyPair(rsaWidth_); // ??????RSA?????????
		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1); // ??????SHA1???????????????????????????
		/**
		 * ???????????????????????????????????????????????????PGP ID??????????????????PGP?????????SecretKey???
		 *
		 * @param certificationLevel         PGP?????????????????????
		 * @param keyPair                    ???????????????????????????
		 * @param id                         ???????????????ID
		 * @param checksumCalculator         ???????????????????????????????????????????????????
		 * @param hashedPcks                 the hashed packets to be added to the
		 *                                   certification.???????????????
		 * @param unhashedPcks               the unhashed packets to be added to the
		 *                                   certification.??????????????????
		 * @param certificationSignerBuilder PGP??????????????????
		 * @param keyEncryptor               ???????????????????????????????????????????????????????????????
		 * @throws PGPException ??????PGP??????
		 */
		return new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity_, sha1Calc, null, null,
				new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				// ?????????????????????
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));
	}

	@SuppressWarnings("restriction")
	public static void main(String[] args) throws Exception {
		String passPhrase_ = "123456789";
		char[] passPhrase = passPhrase_.toCharArray(); // ???passPharse?????????????????????

		PGPSecretKey secretKey = getSecretKey("wathdata", passPhrase_, 2048);

		// ??????????????????-------------??????
		String privateKeyString = Base64.toBase64String(secretKey.getEncoded());
		System.out.println(privateKeyString);

		PGPPublicKey publicKey = secretKey.getPublicKey();
		// FileOutputStream fileOutputStream = new FileOutputStream("c://1.txt");
		byte[] encoded = publicKey.getEncoded();
		// ??????????????????----------------??????
		String publicKeyString = Base64.toBase64String(encoded);
		System.out.println(publicKeyString);

	}

}