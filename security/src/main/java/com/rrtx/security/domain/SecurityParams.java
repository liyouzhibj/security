package com.rrtx.security.domain;

public class SecurityParams {
    public static final int ENCRYPT = 0;
    public static final int DECRYPTE = 1;
    public static final int RSA_PUBLICKEY_FROM_CERT = 0;
    public static final int RSA_PUBLICKEY_FROM_STRING = 1;
    public static final int RSA_PRIVATEKEY_FROM_PFX = 0;
    public static final int RSA_PRIVATEKEY_FROM_STRING = 1;
    public static final int DESKEY_FORMAT_LENGTH = 6;

    /**
     * 加密、解密标志位，0：加密 1：解密
     * */
    private int encryptOrDecryptFlag;

    /**
     * RSA公钥获取途径，0：从证书获取 1：从字符串获取
     * */
    private int rsaPublicKeyFromType;

    /**
     * RSA私钥获取途径 0：从证书获取 1：从字符串获取
     * */
    private int rsaPrivateKeyFromType;

    /**
     * RSA私钥证书路径
     * */
    private String pfxFilePath;

    /**
     * RSA私钥证书加载密码
     * */
    private String pfxFileLoadPassword;

    /**
     * RSA公钥证书路径
     * */
    private String certFilePath;

    /**
     * RSA公钥
     * */
    private String rsaPublicKey;

    /**
     * RSA私钥
     * */
    private String rsaPrivateKey;

    /**
     * 信息
     * */
    private String data;

    public int getEncryptOrDecryptFlag() {
        return encryptOrDecryptFlag;
    }

    public void setEncryptOrDecryptFlag(int encryptOrDecryptFlag) {
        this.encryptOrDecryptFlag = encryptOrDecryptFlag;
    }

    public int getRsaPublicKeyFromType() {
        return rsaPublicKeyFromType;
    }

    public void setRsaPublicKeyFromType(int rsaPublicKeyFromType) {
        this.rsaPublicKeyFromType = rsaPublicKeyFromType;
    }

    public int getRsaPrivateKeyFromType() {
        return rsaPrivateKeyFromType;
    }

    public void setRsaPrivateKeyFromType(int rsaPrivateKeyFromType) {
        this.rsaPrivateKeyFromType = rsaPrivateKeyFromType;
    }

    public String getPfxFilePath() {
        return pfxFilePath;
    }

    public void setPfxFilePath(String pfxFilePath) {
        this.pfxFilePath = pfxFilePath;
    }

    public String getPfxFileLoadPassword() {
        return pfxFileLoadPassword;
    }

    public void setPfxFileLoadPassword(String pfxFileLoadPassword) {
        this.pfxFileLoadPassword = pfxFileLoadPassword;
    }

    public String getCertFilePath() {
        return certFilePath;
    }

    public void setCertFilePath(String certFilePath) {
        this.certFilePath = certFilePath;
    }

    public String getRsaPublicKey() {
        return rsaPublicKey;
    }

    public void setRsaPublicKey(String rsaPublicKey) {
        this.rsaPublicKey = rsaPublicKey;
    }

    public String getRsaPrivateKey() {
        return rsaPrivateKey;
    }

    public void setRsaPrivateKey(String rsaPrivateKey) {
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
