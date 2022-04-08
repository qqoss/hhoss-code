package com.hhoss.util.crypto;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import javax.crypto.Cipher;


public class ReadP12Cert {
public static void main(String[]args){
   final String KEYSTORE_PASSWORD = "credit2go";
   
   try{
    KeyStore ks = KeyStore.getInstance("PKCS12");
	InputStream fis = SignatureProvider.class.getClassLoader().getResourceAsStream("certs/signature.p12");
   
    char[] nPassword = null;
    if((KEYSTORE_PASSWORD == null)||KEYSTORE_PASSWORD.trim().equals("")){
     nPassword = null;
    }else{
     nPassword = KEYSTORE_PASSWORD.toCharArray();
    }
    ks.load(fis,nPassword);
    fis.close();
   
    System.out.println("keystore type = " + ks.getType());
    Enumeration enuml = ks.aliases();
    String keyAlias = null;
    if(enuml.hasMoreElements()){
     keyAlias = (String)enuml.nextElement();
     System.out.println("alias=["+keyAlias+"]");
    }
    System.out.println("is key entry = " + ks.isKeyEntry(keyAlias));
    PrivateKey prikey = (PrivateKey)ks.getKey(keyAlias, nPassword);
    Certificate cert = ks.getCertificate(keyAlias);
    PublicKey pubkey = cert.getPublicKey();
   
    byte[] msg = "犯大汉天威者，虽远必诛！".getBytes("UTF8"); // 待加解密的消息
    Cipher c1 = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // 定义算法：RSA
    c1.init(Cipher.ENCRYPT_MODE, pubkey);
    byte[] msg1 = c1.doFinal(msg); // 加密后的数据
    System.out.println(new String(msg1, "UTF8"));
   
    Cipher c2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    c2.init(Cipher.DECRYPT_MODE, prikey);
    byte[] msg2 = c2.doFinal(msg1); // 解密后的数据

    // 打印解密字符串 - 应显示 犯大汉天威者，虽远必诛！
    System.out.println(new String(msg2, "UTF-8")); // 将解密数据转为字符串

    System.out.println(prikey.toString());
    System.out.println(pubkey.toString());
   }catch(Exception e){
    e.printStackTrace();
   }
}
}
