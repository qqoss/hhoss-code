/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.hhoss.code.ecc;

import static com.hhoss.code.ecc.ECConstant.HEX_PREFIX;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;

import com.hhoss.util.Strings;

/**
 * Message codec functions.
 *
 * <p>
 * Implementation as per
 * https://github.com/ethereum/wiki/wiki/JSON-RPC#hex-value-encoding
 */
public final class Numeric {
	private static final char[] HEX_CHAR_MAP = "0123456789abcdef".toCharArray();

	private Numeric() {
	}

	public static String encodeQuantity(BigInteger value) {
		if (value.signum() != -1) {
			return HEX_PREFIX + value.toString(16);
		} else {
			throw new RuntimeException("Negative values are not supported");
		}
	}

	public static BigInteger decodeQuantity(String value) {
		if (isLongValue(value)) {
			return BigInteger.valueOf(Long.parseLong(value));
		}

		if (!isValidHexQuantity(value)) {
			throw new RuntimeException("Value must be in format 0x[1-9]+[0-9]* or 0x0");
		}
		try {
			return new BigInteger(value.substring(2), 16);
		} catch (NumberFormatException e) {
			throw new RuntimeException("Negative ", e);
		}
	}

	private static boolean isLongValue(String value) {
		try {
			Long.parseLong(value);
			return true;
		} catch (NumberFormatException e) {
			return false;
		}
	}

	private static boolean isValidHexQuantity(String value) {
		if (value == null) {
			return false;
		}

		if (value.length() < 3) {
			return false;
		}

		if (!value.startsWith(HEX_PREFIX)) {
			return false;
		}

		// If TestRpc resolves the following issue, we can reinstate this code
		// https://github.com/ethereumjs/testrpc/issues/220
		// if (value.length() > 3 && value.charAt(2) == '0') {
		// return false;
		// }

		return true;
	}

	public static String cleanHexPrefix(String input) {
		if (containsHexPrefix(input)) {
			return input.substring(2);
		} else {
			return input;
		}
	}

	public static String prependHexPrefix(String input) {
		if (!containsHexPrefix(input)) {
			return HEX_PREFIX + input;
		} else {
			return input;
		}
	}

	public static boolean containsHexPrefix(String input) {
		return input!=null && input.length() > 1 && input.charAt(0) == '0' && input.charAt(1) == 'x';
	}

	public static BigInteger toBigInt(byte[] value, int offset, int length) {
		return toBigInt((Arrays.copyOfRange(value, offset, offset + length)));
	}

	public static BigInteger toBigInt(byte[] value) {
		return new BigInteger(1, value);
	}

	public static BigInteger toBigInt(String hexValue) {
		String cleanValue = cleanHexPrefix(hexValue);
		return new BigInteger(cleanValue, 16);
	}

	public static String toHexStringWithPrefix(BigInteger value) {
		return HEX_PREFIX + value.toString(16);
	}

	public static String toHexString(BigInteger value) {
		return value.toString(16);
	}

	public static String toHexString(byte[] bytes) {
		return new String(toHexCharArray(bytes, 0, bytes.length, false));
	}
	
	public static String toHexWithPrefix(byte[] bytes) {
		return new String(toHexCharArray(bytes, 0, bytes.length, true));
	}
	
	public static String toHexString(byte[] input, int offset, int length, boolean withPrefix) {
		final String output = new String(toHexCharArray(input, offset, length, withPrefix));
		return withPrefix ? new StringBuilder(HEX_PREFIX).append(output).toString() : output;
	}

	public static String toHexStringWithPrefixSafe(BigInteger value) {
		String result = toHexString(value);
		if (result.length() < 2) {
			result = Strings.zeros(1) + result;
		}
		return HEX_PREFIX + result;
	}

	public static String toHexStringPadded(BigInteger value, int size, boolean withPrefix) {
		String result = toHexString(value);

		int length = result.length();
		if (length > size) {
			throw new UnsupportedOperationException("Value " + result + "is larger then length " + size);
		} else if (value.signum() < 0) {
			throw new UnsupportedOperationException("Value cannot be negative");
		}

		if (length < size) {
			result = Strings.zeros(size - length) + result;
		}

		if (withPrefix) {
			return HEX_PREFIX + result;
		} else {
			return result;
		}
	}

	public static byte[] toBytesPadded(BigInteger value, int length) {
		byte[] result = new byte[length];
		byte[] bytes = value.toByteArray();

		int bytesLength;
		int srcOffset;
		if (bytes[0] == 0) {
			bytesLength = bytes.length - 1;
			srcOffset = 1;
		} else {
			bytesLength = bytes.length;
			srcOffset = 0;
		}

		if (bytesLength > length) {
			throw new RuntimeException("Input is too large to put in byte array of size " + length);
		}

		int destOffset = length - bytesLength;
		System.arraycopy(bytes, srcOffset, result, destOffset, bytesLength);
		return result;
	}

	public static byte[] toBytesPadded(String hexStr, int length) {	
		byte[] bytes = hexStringToByteArray(hexStr);
		if(bytes.length < length) {
			byte[] result = new byte[length];
			System.arraycopy(bytes, 0, result, length-bytes.length, bytes.length);
			return result;
		}
		//else if(bytes.length>length) {//should error}

		return bytes;
	}
	
	public static byte[] hexStringToByteArray0(String input) {
		String cleanInput = cleanHexPrefix(input);

		int len = cleanInput.length();

		if (len == 0) {
			return new byte[] {};
		}

		byte[] data;
		int startIdx;
		if (len % 2 != 0) {
			data = new byte[(len / 2) + 1];
			data[0] = (byte) Character.digit(cleanInput.charAt(0), 16);
			startIdx = 1;
		} else {
			data = new byte[len / 2];
			startIdx = 0;
		}

		for (int i = startIdx; i < len; i += 2) {
			data[(i + 1) / 2] = (byte) ((Character.digit(cleanInput.charAt(i), 16) << 4) + Character.digit(cleanInput.charAt(i + 1), 16));
		}
		return data;
	}
	
	/**
	 * @param hexStr the hex String  with optional 0x prefix
	 * @return the bytes
	 */
	public static byte[] hexStringToByteArray(String hexStr) {
		String chs = cleanHexPrefix(hexStr);
		int len = chs.length();
		if (len == 0) {return new byte[]{};}
		byte[] data = new byte[(len+1)/2];
		for (int i = len&1; i < len; i += 2) {
			data[(i+1)/2] = asByte(Character.digit(chs.charAt(i), 16),Character.digit(chs.charAt(i + 1), 16));
		}
		return data;		
	}

	private static char[] toHexCharArray(byte[] input, int offset, int length, boolean withPrefix) {
		final char[] output = new char[length << 1];
		for (int i = offset, j = 0; i < length; i++, j++) {
			final int v = input[i] & 0xFF;
			output[j++] = HEX_CHAR_MAP[v >>> 4];
			output[j] = HEX_CHAR_MAP[v & 0x0F];
		}
		return output;
	}

	public static byte asByte(int m, int n) {
		return (byte) ((m << 4) | n);
	}

	public static boolean isIntegerValue(BigDecimal value) {
		return value.signum() == 0 || value.scale() <= 0 || value.stripTrailingZeros().scale() <= 0;
	}
}
