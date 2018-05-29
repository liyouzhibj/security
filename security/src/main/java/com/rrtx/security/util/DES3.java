package com.rrtx.security.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * 3DES（Triple DES、DESede，进行了三重DES加密的算法）。
 * 具有DES算法相同的特点及弱点。
 * DES、3DES对比如下：
 * 3DES：将密钥长度增至112位或168位，通过增加迭代次数提高安全性
 * 缺点：处理速度较慢、密钥计算时间较长、加密效率不高
 * DES：数据加密标准，是对称加密算法领域中的典型算法
 * 特点：密钥偏短（56位）、生命周期短（避免被破解）
 */
public enum DES3 {
    INSTANCE;

    private Logger logger = LoggerFactory.getLogger(DES3.class);

    /**
     * 3DES生成密钥
     *
     * @return 密钥
     */
    public byte[] generateKey() throws Exception {
        KeyGenerator keyGen;//密钥生成器
        try {
            keyGen = KeyGenerator.getInstance("DESede");
        } catch (NoSuchAlgorithmException e) {
            logger.error("DES3.generateKey: {}", e);
            throw new NoSuchAlgorithmException("3DES生成密钥出现异常");
        }
        keyGen.init(168); //可指定密钥长度为112或168，默认为168
        SecretKey secretKey = keyGen.generateKey();//生成密钥

        return secretKey.getEncoded();
    }


    /**
     * 3DES加密
     *
     * @param key  密钥
     * @param data 明文
     * @return 密文
     */
    public byte[] encrypt(byte[] key, byte[] data) throws Exception{
        SecretKey secretKey = new SecretKeySpec(key, "DESede");//恢复密钥
        Cipher cipher; //Cipher完成加密或解密工作类
        byte[] cipherByte;

        try {
            cipher = Cipher.getInstance("DESede");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);//对Cipher初始化，加密模式
            cipherByte = cipher.doFinal(data);//加密data
        } catch (NoSuchAlgorithmException e) {
            logger.error("DES3.encrypt: {}", e);
            throw new NoSuchAlgorithmException("3DES加密出现异常");
        } catch (NoSuchPaddingException e) {
            logger.error("DES3.encrypt: {}", e);
            throw new NoSuchPaddingException("3DES加密出现异常");
        } catch (InvalidKeyException e) {
            logger.error("DES3.encrypt: {}", e);
            throw new InvalidKeyException("3DES加密出现异常");
        } catch (IllegalBlockSizeException e) {
            logger.error("DES3.encrypt: {}", e);
            throw new IllegalBlockSizeException("3DES加密出现异常");
        } catch (BadPaddingException e) {
            logger.error("DES3.encrypt: {}", e);
            throw new BadPaddingException("3DES加密出现异常");
        }

        return cipherByte;
    }

    /**
     * 解密
     *
     * @param key  密钥
     * @param data 密文
     * @return 明文
     */
    public byte[] decrypt(byte[] key, byte[] data) throws Exception{
        SecretKey secretKey = new SecretKeySpec(key, "DESede");//恢复密钥
        byte[] cipherByte;//解密data
        try {
            Cipher cipher = Cipher.getInstance("DESede");//Cipher完成加密或解密工作类
            cipher.init(Cipher.DECRYPT_MODE, secretKey);//对Cipher初始化，解密模式
            cipherByte = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            logger.error("DES3.decrypt: {}", e);
            throw new NoSuchAlgorithmException("3DES解密出现异常");
        } catch (NoSuchPaddingException e) {
            logger.error("DES3.decrypt: {}", e);
            throw new NoSuchPaddingException("3DES解密出现异常");
        } catch (InvalidKeyException e) {
            logger.error("DES3.decrypt: {}", e);
            throw new InvalidKeyException("3DES解密出现异常");
        } catch (IllegalBlockSizeException e) {
            logger.error("DES3.decrypt: {}", e);
            throw new IllegalBlockSizeException("3DES解密出现异常");
        } catch (BadPaddingException e) {
            logger.error("DES3.decrypt: {}", e);
            throw new BadPaddingException("3DES解密出现异常");
        }
        return cipherByte;
    }
}
