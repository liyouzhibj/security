package com.rrtx.security.service.impl;

import com.rrtx.security.domain.SecurityParams;
import com.rrtx.security.service.ISecurity;
import com.rrtx.security.util.*;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class SecurityImpl implements ISecurity<String, SecurityParams> {
    private static final Logger logger = LoggerFactory.getLogger(SecurityImpl.class);
    private static final Base64 base64 = new Base64();


    private static RSAPublicKey rsaPublicKey;
    private static RSAPrivateKey rsaPrivateKey;


    public String security(SecurityParams securityParams) {
        String result;
        int encOrDecFlag = securityParams.getEncryptOrDecryptFlag();
        int desKeyFormatLength = SecurityParams.DESKEY_FORMAT_LENGTH;

        logger.debug("SecurityImpl.security: encryptOrDecryptFlag value is {}", encOrDecFlag);

        if(securityParams.getData() == null || "".equals(securityParams.getData())){
            logger.error("SecurityImpl.security: 信息不能为空");
            return "";
        }

        logger.debug("SecurityImpl.security: data value is {}", securityParams.getData());

        if (encOrDecFlag == 0) {
            try {
                if (rsaPublicKey == null) {
                    if (securityParams.getRsaPublicKeyFromType() == 0) {
                        String certFilePath = securityParams.getCertFilePath();
                        if (certFilePath == null || "".equals(certFilePath)) {
                            logger.error("SecurityImpl.security: RSA公钥证书路径不能为空");
                            return "";
                        }
                        rsaPublicKey = (RSAPublicKey) CERT.INSTANCE.getPublicKeyFromCert(certFilePath);
                    }

                    if (securityParams.getRsaPublicKeyFromType() == 1) {
                        String rsaPublicKeyStr = securityParams.getRsaPublicKey();
                        if (rsaPublicKeyStr == null || "".equals(rsaPublicKeyStr)) {
                            logger.error("SecurityImpl.security: RSA公钥字符串不能为空");
                            return "";
                        }
                        rsaPublicKey = RSA.INSTANCE.loadPublicKeyByStr(rsaPublicKeyStr);
                    }
                }

                byte[] desKey = DES3.INSTANCE.generateKey();

                String signedData = AddSign.INSTANCE.jsonStringAddSignBySHA256(securityParams.getData());
                byte[] encryptedData = DES3.INSTANCE.encrypt(desKey, signedData.getBytes());
                byte[] encryptedDesKey = RSA.INSTANCE.encrypt(rsaPublicKey, desKey);
                String encryptedDesKeyLength = IntToStrFormat.INSTANCE.intToStrFormatBy0(desKeyFormatLength, encryptedDesKey.length);
                byte[] resultBytes = ByteMerger.INSTANCE.byteMergerAll(encryptedDesKeyLength.getBytes(), encryptedDesKey, encryptedData);
                result = base64.encodeToString(resultBytes).replaceAll("\\+", "%2B");
                logger.debug("SecurityImpl.security: encrypted data is {}", result);

                return result;
            } catch (Exception e) {
                logger.error("SecurityImpl.security: 加密失败，{}", e.getMessage());
                return "";
            }

        }

        if (encOrDecFlag == 1) {
            try {
                if (rsaPrivateKey == null) {
                    if (securityParams.getRsaPrivateKeyFromType() == 0) {
                        String pfxFilePath = securityParams.getPfxFilePath();
                        String pfxFilePassword = securityParams.getPfxFileLoadPassword();
                        if (pfxFilePath == null || "".equals(pfxFilePath)) {
                            logger.error("SecurityImpl.security: RSA私钥证书路径不能为空");
                            return "";
                        }
                        if (pfxFilePassword == null || "".equals(pfxFilePassword)) {
                            logger.error("SecurityImpl.security: RSA私钥证书加载密码不能为空");
                            return "";
                        }

                        rsaPrivateKey = (RSAPrivateKey) CERT.INSTANCE.getPrivateKeyFromPFX(pfxFilePath, pfxFilePassword);
                    }

                    if (securityParams.getRsaPublicKeyFromType() == 1) {
                        String rsaPrivateKeyStr = securityParams.getRsaPrivateKey();
                        if (rsaPrivateKeyStr == null || "".equals(rsaPrivateKeyStr)) {
                            logger.error("SecurityImpl.security: RSA私钥字符串不能为空");
                            return "";
                        }
                        rsaPrivateKey = RSA.INSTANCE.loadPrivateKeyByStr(rsaPrivateKeyStr);
                    }
                }

                byte[] encryptedMessage = base64.decode(securityParams.getData());
                byte[] keyLengthByte = new byte[desKeyFormatLength];
                System.arraycopy(encryptedMessage, 0, keyLengthByte, 0, desKeyFormatLength);

                String keyLengthStr = new String(keyLengthByte);
                int keyLengthInt = Integer.valueOf(keyLengthStr);

                byte[] encryptedDesKey = new byte[keyLengthInt];
                System.arraycopy(encryptedMessage, desKeyFormatLength, encryptedDesKey, 0, keyLengthInt);
                byte[] decryptedDesKey = RSA.INSTANCE.decrypt(rsaPrivateKey, encryptedDesKey);
                byte[] encryptedData = new byte[encryptedMessage.length - desKeyFormatLength - keyLengthInt];
                System.arraycopy(encryptedMessage, desKeyFormatLength + keyLengthInt,
                        encryptedData, 0, encryptedMessage.length - desKeyFormatLength - keyLengthInt);

                byte[] dataByte = DES3.INSTANCE.decrypt(decryptedDesKey, encryptedData);
                result = new String(dataByte);

                if(!CheckSign.INSTANCE.jsonStringCheckSignBySHA256(result)){
                    logger.error("SecurityImpl.security: 校验签名失败");
                    return "";
                }

                logger.debug("SecurityImpl.security: decrypted data is {}", result);

                return result;
            } catch (Exception e) {
                logger.error("SecurityImpl.security: 解密失败，{}", e.getMessage());
                return "";
            }

        }

        return "";
    }
}
