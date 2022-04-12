package com.hhoss.code.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class KeysUtil{

    /**
     *
     * @param Key
     * @return The bitLength of key
     * @throws GeneralSecurityException 
     * @throws Exception 
     * @throws Exception If there is a problem getting the keysize
     */
    public static int getKeyBitLength(Key key) throws GeneralSecurityException  {
		BigInteger bi = getKeyParameter(key);
		if(bi==null){
			throw new GeneralSecurityException("Can't get Key Algorithm length.");
		}
		System.out.println("algorithm:"+key.getAlgorithm()+";class:"+key.getClass().getSimpleName());
		return bi.bitLength();
     }
    
    /**
     * @param key
     * @return the parameter of the key, eg: rsa.modulus,  dsa.prime
     * @throws GeneralSecurityException 
     * @throws Exception
     */
    public static BigInteger getKeyParameter(Key key) throws GeneralSecurityException{
    	BigInteger bint = null ;
     	if(key instanceof RSAKey){
     		bint = ((RSAKey)key).getModulus();
    	}else if(key instanceof DSAKey){
    		bint = ((DSAKey)key).getParams().getP();
    	}else if(key instanceof SecretKey){
       		bint = new BigInteger(((SecretKey)key).getEncoded());
    	}else if(key instanceof ECKey){
    		bint = ((ECKey)key).getParams().getOrder();
    	}
    	return bint;
    }
    
    /**
     * @param key
     * @return the parameter of the key, eg: rsa.modulus,  dsa.prime
     * @throws GeneralSecurityException 
     * @throws Exception
     */
    public static BigInteger getKeyParameter2(Key key) throws GeneralSecurityException{
    	KeyFactory keyFact = KeyFactory.getInstance(key.getAlgorithm());
     	if(key instanceof RSAPublicKey){
    		return keyFact.getKeySpec(key, RSAPublicKeySpec.class).getModulus();
    	}else if(key instanceof RSAPrivateKey){
    		return keyFact.getKeySpec(key, RSAPrivateKeySpec.class).getModulus();
    	}else if(key instanceof DSAPublicKey){
    		return keyFact.getKeySpec(key, DSAPublicKeySpec.class).getP();
    	}else if(key instanceof DSAPrivateKey){
    		return keyFact.getKeySpec(key, DSAPrivateKeySpec.class).getP();
    	}else if(key instanceof SecretKey){
    		return new BigInteger(keyFact.getKeySpec(key, SecretKeySpec.class).getEncoded());
     	}else if(key instanceof ECPublicKey){
    		return keyFact.getKeySpec(key, ECPublicKeySpec.class).getParams().getOrder();
    	}else if(key instanceof ECPrivateKey){
    		return keyFact.getKeySpec(key, ECPrivateKeySpec.class).getS();
    	}
    	return null;
    }
   
    private KeySpec getKeySpec(Key key) throws Exception {
    	String keyClassName = key.getClass().getSimpleName();
    	int idx = keyClassName.lastIndexOf("Key");
    	String ksClassName ="java.security.spec."+keyClassName.substring(0, idx+3)+"Spec";
    	Class ksClass = Class.forName(ksClassName);
    	KeyFactory keyFact = KeyFactory.getInstance(key.getAlgorithm());
    	return  keyFact.getKeySpec(key, ksClass);
    }
    
    public static void main(String[] args) throws Exception{
		String[] algorithms={"RSA","DSA","EC"};
		//default and max 256 for EC
		//DSA Modulus size must range from 512 to 1024(default) and be a multiple of 64
		for(String alg:algorithms){
			KeyPairGenerator keygen = KeyPairGenerator.getInstance(alg);
			//keygen.initialize(128);
			KeyPair keys = keygen.genKeyPair();
			System.out.println(getKeyBitLength(keys.getPublic()));
			System.out.println(getKeyBitLength(keys.getPrivate()));
		}
		
		String[] algs={"DES","AES","DESede","Blowfish","HmacMD5","HmacSHA1"};//,"PBEWithMD5AndDES", "PBEWithMD5AndTripleDES"};
		for(String alg:algs){
			SecretKey key = KeyGenerator.getInstance(alg).generateKey();
			System.out.println(getKeyBitLength(key));
		}
		for(String alg:algs){
			SecretKey key = new SecretKeySpec("hjhfsdjkdfshfjk".getBytes(), alg);
			System.out.println(getKeyBitLength(key));
		}
		/*
		KeyPairGenerator.getInstance("RSA");
		KeyFactory.getInstance("RSA");
		
		SecretKeyFactory.getInstance("DES");
		KeyGenerator.getInstance("DES");
		
		KeyStore.getInstance("AndroidKeyStore");`
		MessageDigest.getInstance("MD5");
		Cipher.getInstance("DES");
		JCE的加解密主要用到一个Class就是Cipher。Cipher类实例在创建时需要指明相关算法和模式（即Cipher.getInstance的参数）。
		根据JCE的要求：可以仅指明“算法”，比如“DES”。要么指明“算法/反馈模式/填充模式”（反馈模式和填充模式都和算法的计算方式有关），比如“AES/CBC/PKCS5Padding”。
		常见的算法有“DES”，“DESede”、“PBEWithMD5AndDES”、“Blowfish”。
		常见的反馈模式有“ECB”、“CBC”、“CFB”、“OFB”、“PCBC”。
		常见的填充模式有“PKCS5Padding”、“NoPadding”。
   		*/
    }
		

}
