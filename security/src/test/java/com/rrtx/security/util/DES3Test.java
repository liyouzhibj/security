package com.rrtx.security.util;

import org.junit.Assert;
import org.junit.Test;

public class DES3Test {

    @Test
    public void des3Test() throws Exception{
        String data = "aaabbbcccdddeeefff";
        String dataCN = "你好，世界！";
        byte[] key = DES3.INSTANCE.generateKey();
        byte[] encryptedData = DES3.INSTANCE.encrypt(key, data.getBytes());
        byte[] encryptedDataCN = DES3.INSTANCE.encrypt(key, dataCN.getBytes());
        byte[] decryptedData = DES3.INSTANCE.decrypt(key, encryptedData);
        byte[] decryptedDataCN = DES3.INSTANCE.decrypt(key, encryptedDataCN);
        Assert.assertEquals(data, new String(decryptedData));
        Assert.assertEquals(dataCN, new String(decryptedDataCN));
    }
}
