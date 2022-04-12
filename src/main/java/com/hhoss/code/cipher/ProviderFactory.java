package com.hhoss.code.cipher;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.hhoss.aspi.Factory;
import com.hhoss.util.token.TokenProvider;

public class ProviderFactory implements Factory<String,TokenProvider> {
  	private static Set<String> supports; 
 
	@Override public TokenProvider get(String name, Object... params){
		if(name==null||params==null||params.length<1){
			throw new IllegalArgumentException("name, param object should not be empty.");
		}

		if(name.endsWith(".cipher")){
			return new CipherProvider();
		}else if(name.endsWith(".crypto")){
			return new CryptoProvider((String[])params);
			//return new CryptoProvider((String[])ConvertUtils.convert(params,String[].class));
		}		
		return null;
	};

	@Override public Set<String> supports() {
		if(supports==null){
			String[] namesArr = {"cipher","crypto"};
			Set<String> names = new HashSet<>();
			for(String name:namesArr){
				names.add(TokenProvider.PREFIX+name);
			}
			supports=Collections.unmodifiableSet(names);
		}
		return supports;
	}
	
}
