package com.hhoss.code.cipher;

import com.hhoss.util.token.TokenProvider;

/**
 * @author kejun
 */

public class CipherProviderTest{	
	private static void test1(){
		TokenProvider provider = TokenProvider.from("cipher", "");
		System.out.println(provider.get("XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(provider.get("$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(provider.get("$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(provider.get("$01$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(provider.get("$des$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(provider.get("$cipher$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(provider.get("$cipher$01$02$XrqJUSe0um8WFMzYs75LvQ=="));
		System.out.println(provider.get("$cipher$des$02$XrqJUSe0um8WFMzYs75LvQ=="));
	}
	
	public static void main(String[] args) throws Exception {
		test1();
	}
}