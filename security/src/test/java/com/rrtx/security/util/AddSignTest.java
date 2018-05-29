package com.rrtx.security.util;

import com.alibaba.fastjson.JSON;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class AddSignTest {

    @Test
    public void addSignTest() throws Exception{
        Map<String, Object> parentMap = new HashMap<String, Object>();
        Map<String, Object> subMap = new HashMap<String, Object>();

        subMap.put("sub", "subTest");
        parentMap.put("name", "zhangsan");
        parentMap.put("email", "zhangsan@163.com");
        parentMap.put("subJson", subMap);

        String jsonString = JSON.toJSONString(parentMap);

        System.out.println(jsonString);

        String result = AddSign.INSTANCE.jsonStringAddSignBySHA256(jsonString);

        System.out.println(result);

        Assert.assertEquals("{\"sign\":\"09A4CCDE81CDCEAA215E84A1FAD6FFD1F9CFF81B27ECD0745EAE5DE580D85D74\",\"email\":\"zhangsan@163.com\",\"name\":\"zhangsan\",\"subJson\":{\"sub\":\"subTest\"}}", result);
    }
}
