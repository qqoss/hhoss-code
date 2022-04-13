package com.hhoss.code.pgp;


import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.*;

public class PgpTest {
   public static void main(String[] args) throws  Exception{
       PgpUtils.getInstance();

       addSigunature();
       verifySigunature();
       encryptFile();
       decryptFile();
   }

   public  static  void addSigunature(){
       byte[] sign= PgpUtils.signatureCreate("/Users/bijia/temp/origin_file.txt",
               "/Users/bijia/temp/self_gen/private-key.txt",
               "/Users/bijia/temp/20191014_sign_file.txt",
               "12345678");
       System.out.println(new String(sign));
   }

   public  static  void verifySigunature(){
       boolean flag = PgpUtils.verifySignature("/Users/bijia/temp/origin_file.txt",
               "/Users/bijia/temp/self_gen/public-key.txt",
               "/Users/bijia/temp/20191014_sign_file.txt");
       System.out.println(flag);
   }


   public  static  void encryptFile()  throws  Exception{
       PgpUtils pgpUtils = PgpUtils.getInstance();
       PGPPublicKey pgpPublicKey = pgpUtils.readPublicKey(new FileInputStream("/Users/bijia/temp/self_gen/public-key.txt"));
       OutputStream os = new FileOutputStream(new File("/Users/bijia/temp/20191014encrypt_file.txt"));
       pgpUtils.encryptFile(os,"/Users/bijia/temp/origin_file.txt",pgpPublicKey,false,false);

   }

   public  static  void decryptFile()  throws  Exception{
       PgpUtils pgpUtils = PgpUtils.getInstance();
       pgpUtils.decryptFile(new FileInputStream(new File("/Users/bijia/temp/20191014encrypt_file.txt")),
               new FileOutputStream(new File("/Users/bijia/temp/20191014decrypt_file.txt")),
               new FileInputStream(new File("/Users/bijia/temp/self_gen/private-key.txt")),
               "12345678".toCharArray());
   }

}