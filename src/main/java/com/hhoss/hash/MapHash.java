package com.hhoss.hash;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

public class MapHash {
	private String spliter="";
	private Iterable<String> ignoredKeys;
	private static final MapHash instance= new MapHash("|");
	
	public MapHash(String spliter){
		this(spliter,new HashSet<String>());
		
	}

	public MapHash(String spliter, Collection<String> ignoredKeys){
		this.spliter=spliter;
		this.ignoredKeys=ignoredKeys;
	}
	
	public MapHash(String spliter, String[] ignoredKeys){
		this.spliter=spliter;
		this.ignoredKeys=Arrays.asList(ignoredKeys);
		//this.ignoredKeys=new HashSet<String>(Arrays.asList(ignoredKeys));
	}
	/**
	 * @param datum
	 * @return hash MD5 first 8 bytes, 64bit long
	 */
	public static long getHashLong(Map<String, Object> map, String spliter){
		String values = instance.getSortedValuesByKey(map);
		//return Digester.encodeByMD5(values);
		//return Hashing.md5().hashBytes(values.getBytes()).asLong();
		return CityHash64.unsignHash(values);
	}

	/**
	 * @param datum
	 * @return hash MD5 first 8 bytes, 64bit long
	 */
	public <T> long getHashLong(Map<String, T> map){
		String values = getSortedValuesByKey(map);
		//return Digester.encodeByMD5(values);
		//return Hashing.md5().hashBytes(values.getBytes()).asLong();
		return CityHash64.unsignHash(values);
	}
	
	public static <T,M extends Map<String,T>> M remove(M map, Iterable<String> keys){
		for(String key:keys){
			map.remove(key);
		}
		return map;
	}
	
	
	//please ensure map.remove("sign") is invoked first;
	public <T> String getSortedValuesByKey(Map<String,T> map){
		Map<String,T> sortedMap = map;
		if(!(map instanceof TreeMap)){
			sortedMap = new TreeMap<>();
			sortedMap.putAll(map);
		}
		StringBuilder sb = new StringBuilder();
		for(Entry<String,T> ent:sortedMap.entrySet()){
			sb.append(spliter);
			if(isIgnored(ent.getKey())){
				continue;
			}
			sb.append(ent.getValue()==null?"":ent.getValue().toString());
		}
		return sb.length()>0?sb.substring(spliter.length()):"";
	}
	
	private boolean isIgnored(String k){
		if(ignoredKeys instanceof Collection){
			return ((Collection<String>)ignoredKeys).contains(k);
		}else{
			for(String key:ignoredKeys){
				if(key.equals(k)){
					return true;
				}
			}
		}
		return false;
	}

}
