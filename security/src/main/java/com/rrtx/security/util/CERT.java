package com.rrtx.security.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public enum CERT {
    INSTANCE;

    private Logger logger = LoggerFactory.getLogger(CERT.class);

    /**
     * 从PFX文件中获取RSA私钥
     *
     * @param pfxFilePath         文件路径
     * @param pfxFileLoadPassword 文件加载密码
     * @return RSA私钥
     */
    public PrivateKey getPrivateKeyFromPFX(String pfxFilePath, String pfxFileLoadPassword) throws Exception {
        return getPrivateKeyFromPFX(pfxFilePath, pfxFileLoadPassword, "PKCS12");
    }

    /**
     * 从PFX文件中获取RSA私钥
     *
     * @param pfxFilePath         文件路径
     * @param pfxFileLoadPassword 文件加载密码
     * @param pfxFileType         文件类型，默认 PKCS12
     * @return RSA私钥
     */
    public PrivateKey getPrivateKeyFromPFX(String pfxFilePath, String pfxFileLoadPassword, String pfxFileType) throws Exception {
        PrivateKey privateKey;

        try {
            KeyStore ks = KeyStore.getInstance(pfxFileType);
            FileInputStream fis = new FileInputStream(pfxFilePath);
            char[] nPassword;
            if ((pfxFileLoadPassword == null) || pfxFileLoadPassword.trim().equals("")) {
                nPassword = null;
            } else {
                nPassword = pfxFileLoadPassword.toCharArray();
            }
            ks.load(fis, nPassword);
            fis.close();
            Enumeration enumas = ks.aliases();
            String keyAlias = null;
            if (enumas.hasMoreElements()) {
                keyAlias = (String) enumas.nextElement();
            }
            privateKey = (PrivateKey) ks.getKey(keyAlias, nPassword);
        } catch (KeyStoreException e) {
            logger.error("CERT.getPrivateKeyFromPFX: {}", e);
            throw new Exception("从PFX文件中获取RSA私钥异常");
        } catch (IOException e) {
            logger.error("CERT.getPrivateKeyFromPFX: {}", e);
            throw new Exception("从PFX文件中获取RSA私钥异常");
        } catch (NoSuchAlgorithmException e) {
            logger.error("CERT.getPrivateKeyFromPFX: {}", e);
            throw new Exception("从PFX文件中获取RSA私钥异常");
        } catch (CertificateException e) {
            logger.error("CERT.getPrivateKeyFromPFX: {}", e);
            throw new Exception("从PFX文件中获取RSA私钥异常");
        } catch (UnrecoverableKeyException e) {
            logger.error("CERT.getPrivateKeyFromPFX: {}", e);
            throw new Exception("从PFX文件中获取RSA私钥异常");
        }

        return privateKey;
    }

    /**
     * 从FPX文件中获取RSA公钥
     *
     * @param pfxFilePath         文件路径
     * @param pfxFileLoadPassword 文件加载目录
     * @return RSA公钥
     */
    public PublicKey getPublicKeyFromPFX(String pfxFilePath, String pfxFileLoadPassword) throws Exception{
        return getPublicKeyFromPFX(pfxFilePath, pfxFileLoadPassword, "PKCS12");
    }

    /**
     * 从FPX文件中获取RSA公钥
     *
     * @param pfxFilePath
     * @param pfxFileLoadPassword
     * @param pfxFileType
     * @return RSA 公钥
     */
    public PublicKey getPublicKeyFromPFX(String pfxFilePath, String pfxFileLoadPassword, String pfxFileType) throws Exception{
        PublicKey publicKey = null;

        try {
            KeyStore ks = KeyStore.getInstance(pfxFileType);
            FileInputStream fis = new FileInputStream(pfxFilePath);
            char[] nPassword;
            if ((pfxFileLoadPassword == null) || pfxFileLoadPassword.trim().equals("")) {
                nPassword = null;
            } else {
                nPassword = pfxFileLoadPassword.toCharArray();
            }
            ks.load(fis, nPassword);
            fis.close();
            Enumeration enumas = ks.aliases();
            String keyAlias = null;
            if (enumas.hasMoreElements()) {
                keyAlias = (String) enumas.nextElement();
            }
            Certificate cert = ks.getCertificate(keyAlias);
            publicKey = cert.getPublicKey();

        } catch (KeyStoreException e) {
            logger.error("CERT.getPublicKeyFromPFX: {}", e);
            throw new Exception("从FPX文件中获取RSA公钥异常");
        } catch (IOException e) {
            logger.error("CERT.getPublicKeyFromPFX: {}", e);
            throw new Exception("从FPX文件中获取RSA公钥异常");
        } catch (NoSuchAlgorithmException e) {
            logger.error("CERT.getPublicKeyFromPFX: {}", e);
            throw new Exception("从FPX文件中获取RSA公钥异常");
        } catch (CertificateException e) {
            logger.error("CERT.getPublicKeyFromPFX: {}", e);
            throw new Exception("从FPX文件中获取RSA公钥异常");
        }

        return publicKey;
    }

    /**
     * 从CERT文件中获取RSA公钥
     *
     * @param certFilePath 文件路径
     *                     @return RSA公钥
     * */
    public PublicKey getPublicKeyFromCert(String certFilePath) throws Exception{
        return getPublicKeyFromCert(certFilePath, "X.509");
    }

    /**
     * 从CERT文件中获取RSA公钥
     *
     * @param certFilePath  文件路径
     * @param certFileType  文件类型，默认 X.509
     * @return RSA公钥
     * */
    public PublicKey getPublicKeyFromCert(String certFilePath, String certFileType) throws Exception{
        PublicKey publicKey = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance(certFileType);
            X509Certificate xcert = (X509Certificate) cf.generateCertificate(new FileInputStream(certFilePath));
            publicKey = xcert.getPublicKey();
        } catch (CertificateException e) {
            logger.error("CERT.getPublicKeyFromCert: {}", e);
            throw new Exception("从CERT文件中获取RSA公钥异常");
        } catch (FileNotFoundException e) {
            logger.error("CERT.getPublicKeyFromCert: {}", e);
            throw new Exception("从CERT文件中获取RSA公钥异常");
        }

        return publicKey;
    }

}
