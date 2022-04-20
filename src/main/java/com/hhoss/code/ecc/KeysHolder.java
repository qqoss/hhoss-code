package com.hhoss.code.ecc;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import com.hhoss.boot.App;


public class KeysHolder {
	public static final String ROOT = "_ROOT";
	private static final Map<String, KeysNode> CACHE = new HashMap<>();	
	static{ initial(); }
	
	private static void initial() {
		String secret = App.getProperty("res.app.module.crypto", "spi.crypto.keys.holder.seed");
		if(secret==null||secret.length()<8) { return; }
		byte[] seed = secret.getBytes();
		setRoot(KeysNode.generateKey(ROOT,seed));
	}
	
	/**
	 * @param child name of the keys,  not null
	 * @param parent name of the keys, not null
	 * @return KeysNode for the name
	 */
	public static KeysNode get(String name,String parent) {	
		if(name==null||parent==null) {return null;}
		if(CACHE.containsKey(name)) {
			return CACHE.get(name);
		}
		return setAndReturn(name,new KeysNode(name,get(parent)));
	}

	/**
	 * @param name keys' name
	 * @return KeysNode for the name, if name is null, it will return the _ROOT
	 */
	private static KeysNode get(String name) {	
		if(name==null||ROOT.equalsIgnoreCase(name)){
			return getRoot();
		}else if(CACHE.containsKey(name)) {
			return CACHE.get(name);
		}
		return setAndReturn(name,new KeysNode(name,getRoot()));
	}
	
	/**
	 * @return root KeysNode
	 */
	private static KeysNode getRoot() {
		if(CACHE.containsKey(ROOT)) {
			return CACHE.get(ROOT);
		}
		return setAndReturn(ROOT,new KeysNode(ROOT));
	}
	
	protected static void setRoot(java.security.KeyPair pair) {
		CACHE.clear();
		CACHE.put(ROOT,new KeysNode(ROOT,pair));
	}
	
	protected static void setRoot(BigInteger priKey) {
		CACHE.clear();
		CACHE.put(ROOT,new KeysNode(ROOT,priKey));
	}	
	
	private static KeysNode setAndReturn(String name, KeysNode keyGen) {
		CACHE.put(name,keyGen);
		return keyGen;
	}

	
}
