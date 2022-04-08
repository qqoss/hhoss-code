package com.hhoss.util.checker;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 验证身份证号码 身份证号码, 可以解析身份证号码的各个字段，以及验证身份证号码是否有效; 身份证号码构成：6位地址编码+8位生日+3位顺序码+1位校验码
 * 
 */
public class Ident {
	private String cardNumber; // 完整的身份证号码
	private Boolean validResult = null; // 缓存身份证是否有效，因为验证有效性使用频繁且计算复杂
	private Date birthDate = null; // 缓存出生日期，因为出生日期使用频繁且计算复杂
	private final static String BIRTH_DATE_FORMAT = "yyyyMMdd"; // 身份证号码中的出生日期的格式
	private final static Date MINIMAL_BIRTH_DATE = new Date(-2209017600000L); // 身份证的最小出生日期,1900年1月1日
	private final static int IDENT_OLD_LENGTH = 15;
	private final static int IDENT_LENGTH = 18;
	private static final char X='X';
	private static final char x='x';

	public boolean validate() {
		if (validResult!=null) {
			return validResult;
		}
		if(cardNumber==null||cardNumber.length()!=IDENT_LENGTH){
			return validResult=false;
		}
		// 身份证号的前17位必须是阿拉伯数字
		for (int i = 0; i < IDENT_LENGTH - 1; i++) {
			char ch = cardNumber.charAt(i);
			if(ch<'0' || ch>'9'){
				return validResult=false;
			}
		}
		if(!validBirth(getBirthDay())){
			return validResult=false;
		}
		char checkCode=genCheckCode(cardNumber);
		char identCode=cardNumber.charAt(IDENT_LENGTH-1);
		if(checkCode!=identCode && identCode!=x){
			return validResult=false;
		}
		// 完整身份证号码的省市县区检验规则
		return false;
	}

	/**
	 * 如果是15位身份证号码，则自动转换为18位
	 * 
	 * @param idNum
	 * @return
	 */
	public Ident(String idNum) {
		if (null != idNum) {
			idNum = idNum.trim();
			if (IDENT_OLD_LENGTH == idNum.length()) {
				idNum = genIdent18(idNum);
			}
		}
		this.cardNumber = idNum;
	}

	public String getCardNumber() {
		return cardNumber;
	}

	public String getAddressCode() {
		this.checkIfValid();
		return this.cardNumber.substring(0, 6);
	}

	public Date getBirthDate() {
		if (null == this.birthDate) {
			try {
				this.birthDate = new SimpleDateFormat(BIRTH_DATE_FORMAT).parse(this.getBirthDay());
			} catch (Exception e) {
				throw new RuntimeException("身份证的出生日期无效");
			}
		}
		return new Date(this.birthDate.getTime());
	}

	public boolean isMale() {
		return 1 == this.getGenderCode();
	}

	public boolean isFemal() {
		return false == this.isMale();
	}

	/**
	 * 获取身份证的第17位，奇数为男性，偶数为女性
	 * 
	 * @return
	 */
	private int getGenderCode() {
		this.checkIfValid();
		char genderCode = this.cardNumber.charAt(IDENT_LENGTH - 2);
		return (genderCode-'0') & 0x1;
	}

	private String getBirthDay() {
		return this.cardNumber.substring(6, 14);
	}

	private void checkIfValid() {
		if (false == this.validate()) {
			throw new RuntimeException("身份证号码不正确！");
		}
	}
	
	public static boolean validArea(String arCode){
		
		return true;
	}
	
	public static boolean validBirth(String birth){
		if(birth==null||birth.length()!=6){
			return false;
		}
		Date birthDate=null;
		try {
			birthDate = new SimpleDateFormat(BIRTH_DATE_FORMAT).parse(birth);
		} catch (ParseException e) {
			return false;
		}
		if(birthDate.after(new Date())|| birthDate.before(MINIMAL_BIRTH_DATE)){
			return false;
		}
		/**
		 * 出生日期中的年、月、日必须正确,比如月份范围是[1,12],日期范围是[1,31]，还需要校验闰年、大月、小月的情况时，月份和日期相符合
		 */
		return (birth.equals(new SimpleDateFormat(BIRTH_DATE_FORMAT).format(birthDate)));
	}

	/**
	 * 校验码（第十八位数）：
	 * 
	 * <br/>十七位数字本体码加权求和公式 S = Sum(Ai * Wi), i = 0...16，先对前17位数字的权求和；
	 * <br/>Ai:表示第i位置上的号码数值
	 * <br/>Wi:表示第i位置上的加权因子 : 2^(17-i); 
	 * <br/>Wi:表示第i位置上的加权因子 : 7 9 10 5 8 4 2 1 6 3 7 9 10 5 8 4 2; (odd+11)/2
	 * <br/>通过模11得到余数: 0 1 2 3 4 5 6 7 8 9 10
	 * <br/>补码的值(12-n): 1 0 X 9 8 7 6 5 4 3 2 
	 * 
	 * @param cardNumber
	 * @return
	 */
	public static char genCheckCode(CharSequence idNumber) {
		if(idNumber==null||idNumber.length()<IDENT_LENGTH-1){
			throw new IllegalArgumentException("id number length should be 18 bits");
		}
		int sum = 0;
		for (int i=1; i<IDENT_LENGTH; i++) {
			char ch = idNumber.charAt(i-1);
			sum += (ch-'0')<<(IDENT_LENGTH-i);
		}
		int check = 12-(sum%11);
		return check==10?X:(char)(check%11+'0');
	}

	/**
	 * 把15位身份证号码转换到18位身份证号码<br>
	 * 15位身份证号码与18位身份证号码的区别为：<br>
	 * 1、15位身份证号码中，"出生年份"字段是2位，转换时需要补入"19"，表示20世纪<br>
	 * 2、15位身份证无最后一位校验码。18位身份证中，校验码根据根据前17位生成
	 * 
	 * @param cardNumber
	 * @return
	 */
	public static String genIdent18(String oldIdent) {
		StringBuilder buf = new StringBuilder(IDENT_LENGTH);
		buf.append(oldIdent.substring(0, 6));
		buf.append("19");
		buf.append(oldIdent.substring(6));
		buf.append(genCheckCode(buf));
		return buf.toString();
	}
	
}
