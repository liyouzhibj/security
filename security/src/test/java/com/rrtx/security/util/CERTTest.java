package com.rrtx.security.util;

import org.junit.Assert;
import org.junit.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class CERTTest {

    @Test
    public void certTest() throws Exception{
        String data = "aaabbbcccdddeeefff";
        RSAPrivateKey privateKey = (RSAPrivateKey) CERT.INSTANCE.getPrivateKeyFromPFX("../keys/opensslTest.pfx", "111111");
        byte[] encryptedData = RSA.INSTANCE.encrypt(privateKey, data.getBytes());
        RSAPublicKey publicKey = (RSAPublicKey) CERT.INSTANCE.getPublicKeyFromPFX("../keys/opensslTest.pfx", "111111");
        byte[] decryptedData = RSA.INSTANCE.decrypt(publicKey, encryptedData);
        Assert.assertEquals(data, new String(decryptedData));

        RSAPublicKey publicKeyFromCert = (RSAPublicKey) CERT.INSTANCE.getPublicKeyFromCert("../keys/openssl.crt");
        byte[] decryptedDataByCertKey = RSA.INSTANCE.decrypt(publicKeyFromCert, encryptedData);
        Assert.assertEquals(data, new String(decryptedDataByCertKey));
    }
}
