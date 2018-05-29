package com.rrtx.security.util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public enum AddSign {
    INSTANCE;

    private Logger logger = LoggerFactory.getLogger(AddSign.class);

    /**
     * JSON字符串使用SHA256添加签名
     *
     * @param jsonString JSON字符串
     * @return 添加签名后的JSON字符串
     */
    public String jsonStringAddSignBySHA256(String jsonString) throws Exception {
        return jsonStringAddSignBySHA256(jsonString, "sign");
    }

    /**
     * JSON字符串使用SHA256添加签名
     *
     * @param jsonString  JSON字符串
     * @param signKeyName 签名添加至JSON字符串时的KEY名
     * @return 添加签名后的JSON字符串
     */
    public String jsonStringAddSignBySHA256(String jsonString, String signKeyName) throws Exception {
        if (jsonString == null || "".equals(jsonString)) {
            logger.error("AddSign.jsonStringAddSignBySHA256: JSON字符串不能为空");
            throw new Exception("JSON字符串使用SHA256添加签名异常");
        }
        if (signKeyName == null || "".equals(signKeyName)) {
            logger.error("AddSign.jsonStringAddSignBySHA256: 签名添加至JSON字符串时的KEY名不能为空");
            throw new Exception("JSON字符串使用SHA256添加签名异常");
        }

        Map<String, Object> map = JSONObject.parseObject(jsonString);

        List<String> list = new ArrayList<String>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            list.add(entry.getKey() + entry.getValue());
        }

        Collections.sort(list);

        String data = "";
        for (String subString : list) {
            data += subString;
        }

        String sign = SHA256.INSTANCE.getSHA256Str(data);

        map.put(signKeyName, sign);

        return JSON.toJSONString(map);
    }
}
