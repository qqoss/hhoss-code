package com.hhoss.hash;
import java.security.MessageDigest;
import java.util.Base64;

import com.hhoss.code.coder.Base58;

public class CryptoUtils {

 
   private static final String ALGORITHM_MD5 = "MD5";
   private static final String ALGORITHM_SHA256 = "SHA-256";
   private static final String ALGORITHM_SHA1 = "SHA-1";
   private static final String CHAT_SET_UTF8 = "UTF-8";
   private static final String ENCODE_STRING_HEX = "hex";
   private static final String ENCODE_STRING_BASE64 = "base64";
   private static final String ENCODE_STRING_BASE58 = "base58";


   //32个字符
   public static String encrypt_md5_hex(String str) {
       return encrypt_hash_function(str, ALGORITHM_MD5, CHAT_SET_UTF8, ENCODE_STRING_HEX);
   }

   //24个字符
   public static String encrypt_md5_base64(String str) {
       return encrypt_hash_function(str, ALGORITHM_MD5, CHAT_SET_UTF8, ENCODE_STRING_BASE64);
   }

   //22个字符
   public static String encrypt_md5_base58(String str) {
       return encrypt_hash_function(str, ALGORITHM_MD5, CHAT_SET_UTF8, ENCODE_STRING_BASE58);
   }

   //40个字符
   public static String encrypt_sha1_hex(String str) {
       return encrypt_hash_function(str, ALGORITHM_SHA1, CHAT_SET_UTF8, ENCODE_STRING_HEX);
   }


   //28个字符
   public static String encrypt_sha1_base64(String str) {
       return encrypt_hash_function(str, ALGORITHM_SHA1, CHAT_SET_UTF8, ENCODE_STRING_BASE64);
   }

   //28个字符
   public static String encrypt_sha1_base58(String str) {
       return encrypt_hash_function(str, ALGORITHM_SHA1, CHAT_SET_UTF8, ENCODE_STRING_BASE58);
   }


   //64个字符
   public static String encrypt_sha256_hex(String str) {
       return encrypt_hash_function(str, ALGORITHM_SHA256, CHAT_SET_UTF8, ENCODE_STRING_HEX);
   }

   //44个字符
   public static String encrypt_sha256_base64(String str) {
       return encrypt_hash_function(str, ALGORITHM_SHA256, CHAT_SET_UTF8, ENCODE_STRING_BASE64);
   }

   //44个字符
   public static String encrypt_sha256_base58(String str) {
       return encrypt_hash_function(str, ALGORITHM_SHA256, CHAT_SET_UTF8, ENCODE_STRING_BASE58);
   }


   private static String encrypt_hash_function(String str, String algorithm, String chatset, String encodeMethod) {
       MessageDigest messageDigest;
       String encodeStr = "";
       try {
           messageDigest = MessageDigest.getInstance(algorithm);
           messageDigest.update(str.getBytes(chatset));

           byte[] digest_bytes = messageDigest.digest();

           if (ENCODE_STRING_BASE64.equals(encodeMethod)) {
               encodeStr = byte2Base64(digest_bytes);
           } else if (ENCODE_STRING_BASE58.equals(encodeMethod)) {
               encodeStr = Base58.encode(digest_bytes);
           } else {
               encodeStr = byte2Hex(digest_bytes);
           }

       } catch (Exception e) {
          //TODO
       }
       return encodeStr;
   }


   private static String byte2Base64(byte[] bytes) {
       return Base64.getEncoder().encodeToString(bytes);
   }


   private static String byte2Hex(byte[] bytes) {
       StringBuffer stringBuffer = new StringBuffer();
       String temp;
       for (int i = 0; i < bytes.length; i++) {
           temp = Integer.toHexString(bytes[i] & 0xFF);
           if (temp.length() == 1) {
               stringBuffer.append("0");
           }
           stringBuffer.append(temp);
       }
       return stringBuffer.toString();
   }


   public static void main(String[] args) {
       String x = encrypt_sha256_base58("12345");
       System.out.println(x);
       System.out.println(x.length());
   }

}