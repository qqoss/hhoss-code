package com.hhoss.code.cipher;

import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.hhoss.code.cipher.CryptoProvider;
import com.hhoss.util.token.TokenProvider;

/**
 * @author kejun
 */

public class CryptoProviderTest{	
	private static void test1(){
		TokenProvider tp = new CryptoProvider();
			tp = TokenProvider.from("crypto", "01","02");
		System.out.println(tp.get("XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(tp.get("$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(tp.get("$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(tp.get("$01$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(tp.get("$des$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(tp.get("$cipher$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(tp.get("$cipher$01$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(tp.get("$cipher$des$02$XrqJUSe0um8WFMzYs75LvQ=="));
	}
	
	public static void test2() throws Exception {
		SecretKey sk = KeyGenerator.getInstance("des").generateKey();
		System.out.println(Arrays.toString(sk.getEncoded()));
	}
	
	public static void main(String[] args) throws Exception {
		test1();
	}
}