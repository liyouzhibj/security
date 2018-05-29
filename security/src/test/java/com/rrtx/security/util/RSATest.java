package com.rrtx.security.util;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RSATest {
    private static final Logger logger = LoggerFactory.getLogger(RSATest.class);

    @Test
    public void rsaTest() throws Exception{
        String data = "aaabbbcccdddeeefff";

        RSA.INSTANCE.genKeyPair("../keys/");

        File pkcs8_rsa_private_key = new File("../keys/pkcs8_rsa_private_key.pem");
        Assert.assertTrue(pkcs8_rsa_private_key.exists());

        File rsa_public_key = new File("../keys/rsa_public_key.pem");
        Assert.assertTrue(rsa_public_key.exists());

        RSA.INSTANCE.genKeyPair("../keys/", "publicKey.pem", "privateKey.pem");

        File publicKey = new File("../keys/publicKey.pem");
        Assert.assertTrue(publicKey.exists());

        File privateKey = new File("../keys/privateKey.pem");
        Assert.assertTrue(privateKey.exists());

        RSAPublicKey rsaPublicKey = RSA.INSTANCE.loadPublicKeyByFile("../keys/publicKey.pem");
        byte[] encryptedData = RSA.INSTANCE.encrypt(rsaPublicKey, data.getBytes());
        RSAPrivateKey rsaPrivateKey = RSA.INSTANCE.loadPrivateKeyByFile("../keys/privateKey.pem");

        byte[] decryptedData = RSA.INSTANCE.decrypt(rsaPrivateKey, encryptedData);

        Assert.assertEquals(data, new String(decryptedData));
    }
}
