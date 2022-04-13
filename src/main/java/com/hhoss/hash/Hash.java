/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.hhoss.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.jcajce.provider.digest.Blake2b;
import org.bouncycastle.jcajce.provider.digest.Keccak;

import com.hhoss.code.ecc.Numeric;

/** Cryptographic hash functions. 
 * 
 * */
public class Hash {
	
	public static byte[] hash(String algorithm, byte[] data) {
		try {
			/*
			MessageDigest mdInst = MessageDigest.getInstance(algorithm);// 使用指定的字节更新摘要
			mdInst.update(data);	// 获得密文
			return mdInst.digest();
			*/
			return MessageDigest.getInstance(algorithm).digest(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Keccak-256 hash function that operates on a UTF-8 encoded String.
	 *
	 * @param utf8Str UTF-8 encoded string
	 * @return hash value as hex encoded string
	 */
	public static String sha3String(String utf8Str) {
		byte[] bytes = utf8Str.getBytes(StandardCharsets.UTF_8);
		return Numeric.toHexString(sha3(bytes));
	}

	/**
	 * Keccak-256 hash function.
	 *
	 * @param input  binary encoded input data
	 * @param offset of start of data
	 * @param length of data
	 * @return hash value
	 */
	public static byte[] sha3(byte[] input, int offset, int length) {
		Keccak.DigestKeccak kecc = new Keccak.Digest256();
		kecc.update(input, offset, length);
		return kecc.digest();
	}

	/**
	 * Keccak-256 hash function.
	 *
	 * @param input binary encoded input data
	 * @return hash value
	 */
	public static byte[] sha3(byte[] input) {
		return sha3(input, 0, input.length);
	}

	/**
	 * Generates SHA-256 digest for the given {@code input}.
	 *
	 * @param input The input to digest
	 * @return The hash value for the given input
	 * @throws RuntimeException If we couldn't find any SHA-256 provider
	 */
	public static byte[] sha256(byte[] input) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Couldn't find a SHA-256 provider", e);
		}
	}
	

	public static byte[] sha256hash160(byte[] input) {
		byte[] sha256 = sha256(input);
		return RIPEMD160(sha256);
	}
	
	public static byte[] RIPEMD160(byte[] input) {
		RIPEMD160Digest digest = new RIPEMD160Digest();
		digest.update(input, 0, input.length);
		byte[] out = new byte[digest.getDigestSize()]; //size=20
		digest.doFinal(out, 0);
		return out;
	}

	/**
	 * Blake2-256 hash function.
	 *
	 * @param input binary encoded input data
	 * @return hash value
	 */
	public static byte[] blake2b256(byte[] input) {
		return new Blake2b.Blake2b256().digest(input);
	}
}
