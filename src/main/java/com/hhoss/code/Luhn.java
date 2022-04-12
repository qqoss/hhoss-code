package com.hhoss.code;

/**
 * 卡号码必须通过Luhn算法来验证通过。 该校验的过程：
 * 1、从卡号最后一位数字开始，逆向将奇数位(1、3、5等等)相加。
 * 2、从卡号最后一位数字开始，逆向将偶数位数字，先乘以2，（如果乘积为两位数，则两个数字再相加（或者将其减去9）），再求和。
 * 3、将奇数位总和加上偶数位总和，结果应该可以被10整除。
 */

import java.util.Scanner;

/**
 * @author kejun
 *
 */
public class Luhn {

	/**
	 * @param card number to validate
	 * @return true id pass the validate
	 */
	public static boolean validate(String card){
		return card.charAt(card.length()-1)-'0'==genCheck(card, true);
	}

	/**
	 * @param card number to validate
	 * @return true id pass the validate
	 */
	public static boolean validate(long card){
		return card%10==genCheck(card/10);
	}
	
	/**
	 * @param bin the cardbin 9 nums
	 * @param seq the seq belongs to the card , not include check bit.
	 * @return 19 bit cardnumber
	 */
	public static long getCard(int bin, int seq){
	   long card=1000000000l*bin+seq;
	   return card=card*10+genCheck(card);
	}
	
	/**
	 * @param bin the cardbin nums
	 * @param seq the seq belongs to the card , not include check bit.
	 * @return string of 19 bit cardnumber
	 */
	public static String genCard(int bin, int seq){
	   return genCard(String.valueOf(bin),String.valueOf(seq),19);
	}
	
	/**
	 * @param bin the cardbin nums
	 * @param seq the seq belongs to the card , not include check bit.
	 * @param len the result card numbers length.
	 * @return string of card number
	 */
	public static String genCard(int bin, int seq, int len){
		return genCard(String.valueOf(bin),String.valueOf(seq),len);
	}
	
	/**
	 * @param bin the cardbin nums
	 * @param seq the seq belongs to the card , not include check bit.
	 * @param len the result card numbers length.
	 * @return string of card number
	 */
	public static String genCard(String bin, String seq, int len){
	   char[] chrs = new char[len-1];
	   char[] bins = bin.toCharArray();
	   char[] seqs = seq.toCharArray();
	   
	   System.arraycopy(bins, 0, chrs, 0, bins.length);
	   System.arraycopy(seqs, 0, chrs, chrs.length-seqs.length, seqs.length);
	   for(int i=bins.length;i<chrs.length-seqs.length;i++){chrs[i]='0';}
	   String card=new String(chrs);
	   return card+=genCheck(card);
	}	
	
	/**
	 * @param num without the check bit
	 * @return the checkNumber
	 */
	public static int genCheck(long num){
		return genCheck(String.valueOf(num),false);
	}
	
	/**
	 * @param num without the check bit
	 * @return the checkNumber
	 */
	public static int genCheck(String num){
		return genCheck(num,false);
	}

	/**
	 * @param cardNum the card number  
	 * @param withCheck true if the last number is the cardNum. 
	 * @return the num of check value
	 */
	
	public static int genCheck(String cardNum, boolean withCheck){
		int len=cardNum.length()-(withCheck?1:0); 
		int o=len%2; int sum=0;
		char[] nums = cardNum.toCharArray();
		for(int i=0;i<len;i++){
			int n = nums[i]-'0';
			sum+=(i%2==o)?n:n+((n>4)?(n-9):n);
		}
		return (10-sum%10)%10;
	}
	
	/**
	 * @param cardNum
	 * @param withCheck
	 * @return
	 */
	 @Deprecated
	public static int genCheck2(String cardNum, boolean withCheck){
		int sum = 0; int c=withCheck?1:0;
		char[] nums = reverse(cardNum.toCharArray());
		for(int i=0;i<nums.length-c;i++){
			int n = nums[i+c]-'0';
			sum+=(i%2==0)?n+((n>4)?(n-9):n):n;
		}
		return (10-sum%10)%10;
	}

	/**
	 * reverse one array, and return,not create new Array.
	 * synchronized arrs when handling
	 * @param arrs
	 * @return the array has been reversed, not new reference!
	 */
	public static <T> T[] reverse(T[] arrs) {
		synchronized(arrs){
		  for (int head=0,tail=arrs.length-1; head<tail; head++,tail--) {
	        T temp = arrs[tail];
	        arrs[tail] = arrs[head];
	        arrs[head] = temp;
	    }}
	    return arrs;
	}
	
	public static char[] reverse(char[] arrs) {
		synchronized(arrs){
		  for (int head=0,tail=arrs.length-1; head<tail; head++,tail--) {
			char temp = arrs[tail];
	        arrs[tail] = arrs[head];
	        arrs[head] = temp;
	    }}
	    return arrs;
	}
	
}
