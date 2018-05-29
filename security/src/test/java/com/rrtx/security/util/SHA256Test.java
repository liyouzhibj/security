package com.rrtx.security.util;

import org.junit.Assert;
import org.junit.Test;

public class SHA256Test {

    @Test
    public void sha246Test() throws Exception{
        String sourceStr = "aaabbbcccdddeeefff";
        String result = SHA256.INSTANCE.getSHA256Str(sourceStr);
        Assert.assertEquals("5662CF7AB1070E448A9D28B4D39C188EEBCC91B66F309F9C415C24A815C82A04",result);

        String sourceStrGBK = "你好，世界";
        String resultGBK = SHA256.INSTANCE.getSHA256Str(sourceStrGBK, "HHH");
        Assert.assertEquals("3BCD0BB22B4D7598A91AF3E8AA4065F8C7D5BD5A8C60BCD4FC24B50768702C81", resultGBK);
    }

}
