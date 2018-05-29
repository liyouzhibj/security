package com.rrtx.security.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 安全散列算法（英语：Secure Hash Algorithm，缩写为SHA）是一个密码散列函数家族，是FIPS所认证的安全散列算法。
 * 能计算出一个数字消息所对应到的，长度固定的字符串（又称消息摘要）的算法。
 * 且若输入的消息不同，它们对应到不同字符串的机率很高。
 * 对称密钥算法。
 */
public enum SHA256 {
    INSTANCE;

    private Logger logger = LoggerFactory.getLogger(SHA256.class);

    public String getSHA256Str(String sourceStr) throws Exception {
        return getSHA256Str(sourceStr, "UTF-8");
    }

    /**
     * 对 sourceStr 计算消息摘要
     *
     * @param sourceStr 源字符串
     * @return 经过SHA256加密后的字符串
     */
    public String getSHA256Str(String sourceStr, String charset) throws Exception {
        MessageDigest messageDigest;
        String encodeStr = "";

        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(sourceStr.getBytes(charset));
            encodeStr = ByteToString.INSTANCE.byte2Hex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            logger.error("SHA256.getSHA256Str: {}", e);
            throw new Exception("计算消息摘要出现异常");
        } catch (UnsupportedEncodingException e) {
            logger.error("SHA256.getSHA256Str: {}", e);
            throw new Exception("计算消息摘要出现异常");
        }

        return encodeStr.toUpperCase();
    }

}
