package com.hhoss.util.checker;

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
public class LuhnTest {
	
	public static void test1(){
		System.out.println(genCheck2("621246167000000110",false));
		System.out.println(genCheck2("621246167000000111",false));
		System.out.println(genCheck2("621246167000000112",false));
		System.out.println(genCheck2("621246167000000113",false));
		System.out.println(genCheck2("621246167000000114",false));
		System.out.println(genCheck2("621246167000000115",false));
		System.out.println(getBankCardCheckCode("621246167000000110"));
		System.out.println(getBankCardCheckCode("621246167000000111"));
		System.out.println(getBankCardCheckCode("621246167000000112"));
		System.out.println(getBankCardCheckCode("621246167000000113"));
		System.out.println(getBankCardCheckCode("621246167000000114"));
		System.out.println(getBankCardCheckCode("621246167000000115"));
		System.out.println(check3("6212461670000001101"));
		System.out.println(check3("6212461670000001110"));
		System.out.println(check3("6212461670000001129"));
		System.out.println(check3("6212461670000001138"));
		System.out.println(check3("6212461670000001146"));
		System.out.println(check3("6212461670000001153"));
		System.out.println(Luhn.getCard(621246167,110));
		System.out.println(Luhn.getCard(621246167,111));
		System.out.println(Luhn.getCard(621246167,112));
		System.out.println(Luhn.getCard(621246167,113));
		System.out.println(Luhn.getCard(621246167,114));
		System.out.println(Luhn.getCard(621246167,115));
		System.out.println(Luhn.genCard(621246105,19141));
		System.out.println(Luhn.getCard(621246105,20417));
		System.out.println(Luhn.genCard(621246105,20417));
		System.out.println(Luhn.getCard(621246105,20520));
		System.out.println(Luhn.genCard(621246105,20520));
		System.out.println(Luhn.getCard(621246105,20504));
		System.out.println(Luhn.genCard(621246105,20504));
	
		
		System.out.println(Luhn.validate("6212461050000191411"));
		System.out.println(Luhn.validate("6212461050000191413"));
		System.out.println(Luhn.validate("6212461050000191412"));
		System.out.println(Luhn.validate("6250760004176619"));
		System.out.println(Luhn.validate("6250760004176617"));
		
	}
	
	public static void input(){
		Scanner in = new Scanner(System.in);
		System.out.println("请输入卡号：");
		String strNum = in.next();
		while(strNum.indexOf('q')==-1) {
			if (Luhn.validate(strNum)) {
				System.out.println("卡号有效！请输入：");
			} else {
				System.out.println("卡号无效！请输入：");
			}
			strNum = in.next();
		}
		in.close();
	}

	public static void main(String[] args) {
		test1();
		input();
	}
	
	public static int genCheck2(String cardNum, boolean withCheck){
		int sum = 0; int c=withCheck?1:0;
		char[] nums = reverse(cardNum.toCharArray());
		for(int i=0;i<nums.length-c;i++){
			int n = nums[i+c]-'0';
			sum+=(i%2==0)?n+((n>4)?(n-9):n):n;
		}
		return (10-sum%10)%10;
	}

	public static boolean check3(String cardNo) {
		int[] cardNoArr = new int[cardNo.length()];
		for (int i = 0; i < cardNo.length(); i++) {
			cardNoArr[i] = Integer.valueOf(String.valueOf(cardNo.charAt(i)));
		}

		for (int i = cardNoArr.length - 2; i >= 0; i -= 2) {
			cardNoArr[i] <<= 1;
			cardNoArr[i] = cardNoArr[i] / 10 + cardNoArr[i] % 10;
		}

		int sum = 0;
		for (int i = 0; i < cardNoArr.length; i++) {
			sum += cardNoArr[i];
		}
		return sum % 10 == 0;

	}
	
	
    public static boolean check4(String cardId) {  
        char bit = getBankCardCheckCode(cardId.substring(0, cardId.length() - 1));  
        return cardId.charAt(cardId.length() - 1) == bit;          
    }  
      
    /** 
     * 从不含校验位的银行卡卡号采用 Luhm 校验算法获得校验位 
     * @param nonCheckCodeCardId 
     * @return 
     */  
    public static char getBankCardCheckCode(String nonCheckCodeCardId) {  
        if(nonCheckCodeCardId == null || nonCheckCodeCardId.trim().length() == 0 || !nonCheckCodeCardId.matches("\\d+")) {  
            throw new IllegalArgumentException("Bank card code must be number!");  
        }  
        char[] chs = nonCheckCodeCardId.trim().toCharArray();  
        int luhmSum = 0;  
        for(int i = chs.length - 1, j = 0; i >= 0; i--, j++) {  
            int k = chs[i] - '0';  
            if(j % 2 == 0) {  
                k *= 2;  
                k = k / 10 + k % 10;  
            }  
            luhmSum += k;              
        }  
        return (luhmSum % 10 == 0) ? '0' : (char)((10 - luhmSum % 10) + '0');  
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
