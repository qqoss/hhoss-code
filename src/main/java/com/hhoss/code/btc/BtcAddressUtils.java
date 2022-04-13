package com.hhoss.code.btc;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import com.hhoss.code.coder.Base58;
import com.hhoss.hash.Hash;

/**
 * 地址工具类
 *
 * @author wangwei
 * @date 2018/03/21
 */
public class BtcAddressUtils {
    
    /**
     * 双重Hash
     *
     * @param data
     * @return
     */
    public static byte[] doubleHash(byte[] data) {
        return Hash.sha256(Hash.sha256(data));
    }

    /**
     * 计算公钥的 RIPEMD160 Hash值
     *
     * @param pubKey 公钥
     * @return ipeMD160Hash(sha256 ( pubkey))
     */
    public static byte[] ripeMD160Hash(byte[] pubKey) {
        //1. 先对公钥做 sha256 处理
    	return Hash.RIPEMD160(Hash.sha256(pubKey));
    }

    /**
     * 生成公钥的校验码
     *
     * @param payload
     * @return
     */
    public static byte[] checksum(byte[] payload) {
        return Arrays.copyOfRange(doubleHash(payload), 0, 4);
    }
    
    public String getAddress(byte[] pubKey) throws Exception {
        // 1. 获取 ripemdHashedKey
        //byte[] ripemdHashedKey = BtcAddressUtils.ripeMD160Hash(this.getPublicKey().getEncoded());
        byte[] ripemdHashedKey = ripeMD160Hash(pubKey);

        // 2. 添加版本 0x00
        ByteArrayOutputStream addrStream = new ByteArrayOutputStream();
        addrStream.write((byte) 0);
        addrStream.write(ripemdHashedKey);
        byte[] versionedPayload = addrStream.toByteArray();

        // 3. 计算校验码
        byte[] checksum = checksum(versionedPayload);

        // 4. 得到 version + paylod + checksum 的组合
        addrStream.write(checksum);
        byte[] binaryAddress = addrStream.toByteArray();

        // 5. 执行Base58转换处理
        //return Base58Check.rawBytesToBase58(binaryAddress);
        return Base58.encode(binaryAddress);
    }


}