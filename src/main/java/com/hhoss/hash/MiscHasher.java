package com.hhoss.hash;

/**
 * Hash算法大全<br>
 * 推荐使用FNV1算法
 * @algorithm None
 * @author Goodzzp 2006-11-20
 * @lastEdit zhengkejun 2015-09-20
 * @editDetail Create
http://www.cnblogs.com/uvsjoh/archive/2012/03/27/2420120.html#
 * Hash函数 数据1 数据2 数据3 数据4 数据1得分 数据2得分 数据3得分 数据4得分 平均分 
	BKDRHash 2 0 4774 481 96.55 100 90.95 82.05 92.64 
	APHash 2 3 4754 493 96.55 88.46 100 51.28 86.28 
	DJBHash 2 2 4975 474 96.55 92.31 0 100 83.43 
	JSHash 1 4 4761 506 100 84.62 96.83 17.95 81.94 
	RSHash 1 0 4861 505 100 100 51.58 20.51 75.96 
	SDBMHash 3 2 4849 504 93.1 92.31 57.01 23.08 72.41 
	PJWHash 30 26 4878 513 0 0 43.89 0 21.95 
	ELFHash 30 26 4878 513 0 0 43.89 0 21.95 
其中数据1为100000个字母和数字组成的随机串哈希冲突个数。数据2为100000个有意义的英文句子哈希冲突个数。数据3为数据1的哈希值与 1000003(大素数)求模后存储到线性表中冲突的个数。数据4为数据1的哈希值与10000019(更大素数)求模后存储到线性表中冲突的个数。
经过比较，得出以上平均得分。平均数为平方平均数。可以发现，BKDRHash无论是在实际效果还是编码实现中，效果都是最突出的。APHash也是较为优秀的算法。DJBHash,JSHash,RSHash与SDBMHash各有千秋。PJWHash与ELFHash效果最差，但得分相似，其算法本质是相似的。

 */ 
 public class MiscHasher { 
     /**//**
     * 加法hash
     * @param key 字符串
    * @param prime 一个质数
    * @return hash结果
    */ 
     public static int additiveHash(String key, int prime) 
     { 
         int hash, i; 
         for (hash = key.length(), i = 0; i < key.length(); i++) 
             hash += key.charAt(i); 
         return (hash % prime); 
     } 
      
     /**//**
     * 旋转hash
     * @param key 输入字符串
    * @param prime 质数
    * @return hash值
    */ 
     public static int rotatingHash(String key, int prime) 
     { 
         int hash, i; 
         for (hash=key.length(), i=0; i<key.length(); ++i) 
             hash = (hash<<4)^(hash>>28)^key.charAt(i); 
         return (hash % prime); 
         //   return (hash ^ (hash>>10) ^ (hash>>20)); 
     } 
      
     // 替代： 
     // 使用：hash = (hash ^ (hash>>10) ^ (hash>>20)) & mask; 
     // 替代：hash %= prime; 
  
     /**//**
     * 一次一个hash
     * @param key 输入字符串
    * @return 输出hash值
    */ 
     public static int oneByOneHash(String key) 
     { 
         int   hash, i; 
         for (hash=0, i=0; i<key.length(); ++i) 
         { 
             hash += key.charAt(i); 
             hash += (hash << 10); 
             hash ^= (hash >> 6); 
         } 
         hash += (hash << 3); 
         hash ^= (hash >> 11); 
         hash += (hash << 15); 
         //   return (hash & M_MASK); 
         return hash; 
     } 
      
     /**//**
     * Bernstein's hash
     * @param key 输入字节数组
    * @param level 初始hash常量
    * @return 结果hash
     */ 
     public static int bernstein(String key) 
     { 
         int hash = 0; 
         int i; 
         for (i=0; i<key.length(); ++i) hash = 33*hash + key.charAt(i); 
         return hash; 
     } 
      
     // 
     /**///// Pearson's Hash 
     // char pearson(char[]key, ub4 len, char tab[256]) 
     // { 
     //   char hash; 
     //   ub4 i; 
     //   for (hash=len, i=0; i<len; ++i) 
     //     hash=tab[hash^key[i]]; 
     //   return (hash); 
     // } 
      
     /**///// CRC Hashing，计算crc,具体代码见其他 
     // ub4 crc(char *key, ub4 len, ub4 mask, ub4 tab[256]) 
     // { 
     //   ub4 hash, i; 
     //   for (hash=len, i=0; i<len; ++i) 
     //     hash = (hash >> 8) ^ tab[(hash & 0xff) ^ key[i]]; 
     //   return (hash & mask); 
     // } 
      
     /**//**
     * Universal Hashing
     */ 
     public static int universal(char[]key, int mask, int[] tab) 
     { 
         int hash = key.length, i, len = key.length; 
         for (i=0; i<(len<<3); i+=8) 
         { 
             char k = key[i>>3]; 
             if ((k&0x01) == 0) hash ^= tab[i+0]; 
             if ((k&0x02) == 0) hash ^= tab[i+1]; 
             if ((k&0x04) == 0) hash ^= tab[i+2]; 
             if ((k&0x08) == 0) hash ^= tab[i+3]; 
             if ((k&0x10) == 0) hash ^= tab[i+4]; 
             if ((k&0x20) == 0) hash ^= tab[i+5]; 
             if ((k&0x40) == 0) hash ^= tab[i+6]; 
             if ((k&0x80) == 0) hash ^= tab[i+7]; 
         } 
         return (hash & mask); 
     } 
      
     /**//**
     * Zobrist Hashing
     */ 
     public static int zobrist( char[] key,int mask, int[][] tab) 
     { 
         int hash, i; 
         for (hash=key.length, i=0; i<key.length; ++i) 
             hash ^= tab[i][key[i]]; 
         return (hash & mask); 
     } 
      
      
     /**//**
     * Thomas Wang的算法，整数hash
     */ 
     public static int intHash(int key) 
     { 
         key += ~(key << 15); 
         key ^= (key >>> 10); 
         key += (key << 3); 
         key ^= (key >>> 6); 
         key += ~(key << 11); 
         key ^= (key >>> 16); 
         return key; 
     } 
     /**//**
     * RS算法hash
     * @param str 字符串
    */ 
     public static int RSHash(String str) 
     { 
         int b    = 378551; 
         int a    = 63689; 
         int hash = 0; 
          
         for(int i = 0; i < str.length(); i++) 
         { 
             hash = hash * a + str.charAt(i); 
             a    = a * b; 
         } 
          
         return (hash & 0x7FFFFFFF); 
     } 
     /**//* End Of RS Hash Function */ 
      
     /**//**
     * JS算法
    */ 
     public static int JSHash(String str) 
     { 
         int hash = 1315423911; 
          
         for(int i = 0; i < str.length(); i++) 
         { 
             hash ^= ((hash << 5) + str.charAt(i) + (hash >> 2)); 
         } 
          
         return (hash & 0x7FFFFFFF); 
     } 
     /**//* End Of JS Hash Function */ 
      
     /**//**
     * PJW算法
    */ 
     public static int PJWHash(String str) 
     { 
         int BitsInUnsignedInt = 32; 
         int ThreeQuarters     = (BitsInUnsignedInt * 3) / 4; 
         int OneEighth         = BitsInUnsignedInt / 8; 
         int HighBits          = 0xFFFFFFFF << (BitsInUnsignedInt - OneEighth); 
         int hash              = 0; 
         int test              = 0; 
          
         for(int i = 0; i < str.length();i++) 
         { 
             hash = (hash << OneEighth) + str.charAt(i); 
              
             if((test = hash & HighBits) != 0) 
             { 
                 hash = (( hash ^ (test >> ThreeQuarters)) & (~HighBits)); 
             } 
         } 
          
         return (hash & 0x7FFFFFFF); 
     } 
     /**//* End Of P. J. Weinberger Hash Function */ 
      
     /**//**
     * ELF算法
    */ 
     public static int ELFHash(String str) 
     { 
         int hash = 0; 
         int x    = 0; 
          
         for(int i = 0; i < str.length(); i++) 
         { 
             hash = (hash << 4) + str.charAt(i); 
             if((x = (int)(hash & 0xF0000000L)) != 0) 
             { 
                 hash ^= (x >> 24); 
                 hash &= ~x; 
             } 
         } 
          
         return (hash & 0x7FFFFFFF); 
     } 
     /**//* End Of ELF Hash Function */ 
      
     /**//**
     * BKDR算法
    */ 
     public static int BKDRHash(String str) 
     { 
         int seed = 131; // 31 131 1313 13131 131313 etc.. 
         int hash = 0; 
          
         for(int i = 0; i < str.length(); i++) 
         { 
             hash = (hash * seed) + str.charAt(i); 
         } 
          
         return (hash & 0x7FFFFFFF); 
     } 
     /**//* End Of BKDR Hash Function */ 
      
     /**//**
     * SDBM算法
    */ 
     public static int SDBMHash(String str) 
     { 
         int hash = 0; 
          
         for(int i = 0; i < str.length(); i++) 
         { 
             hash = str.charAt(i) + (hash << 6) + (hash << 16) - hash; 
         } 
          
         return (hash & 0x7FFFFFFF); 
     } 
     /**//* End Of SDBM Hash Function */ 
      
     /**//**
     * DJB算法
    */ 
     public static int DJBHash(String str) 
     { 
         int hash = 5381; 
          
         for(int i = 0; i < str.length(); i++) 
         { 
             hash = ((hash << 5) + hash) + str.charAt(i); 
         } 
          
         return (hash & 0x7FFFFFFF); 
     } 
     /**//* End Of DJB Hash Function */ 
      
     /**//**
     * DEK算法
    */ 
     public static int DEKHash(String str) 
     { 
         int hash = str.length(); 
          
         for(int i = 0; i < str.length(); i++) 
         { 
             hash = ((hash << 5) ^ (hash >> 27)) ^ str.charAt(i); 
         } 
          
         return (hash & 0x7FFFFFFF); 
     } 
     /**//* End Of DEK Hash Function */ 
      
     /**//**
     * AP算法
    */ 
     public static int APHash(String str) 
     { 
         int hash = 0; 
          
         for(int i = 0; i < str.length(); i++) 
         { 
             hash ^= ((i & 1) == 0) ? ( (hash << 7) ^ str.charAt(i) ^ (hash >> 3)) : 
         (~((hash << 11) ^ str.charAt(i) ^ (hash >> 5))); 
         } 
          
         //       return (hash & 0x7FFFFFFF); 
         return hash; 
     } 
     /**//* End Of AP Hash Function */ 
      
     /**//**
     * JAVA自己带的算法
    */ 
     public static int javaHash(String str) {
    	 //return str.hashCode();
         int h = 0; 
         int off = 0; 
         int len = str.length(); 
         for (int i = 0; i < len; i++) 
         { 
             h = 31 * h + str.charAt(off++); 
         } 
         return h; 
     } 
  }