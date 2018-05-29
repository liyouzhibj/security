package com.rrtx.security.util;

import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public enum CheckSign {
    INSTANCE;

    private Logger logger = LoggerFactory.getLogger(CheckSign.class);

    /**
     * JSON字符串使用SHA256校验签名
     *
     * @param jsonString JSON字符串
     * @return 添加签名后的JSON字符串
     */
    public boolean jsonStringCheckSignBySHA256(String jsonString) throws Exception {
        return jsonStringCheckSignBySHA256(jsonString, "sign");
    }

    /**
     * JSON字符串使用SHA256校验签名
     *
     * @param jsonString  JSON字符串
     * @param signKeyName 签名在JSON字符串时的KEY名
     * @return 添加签名后的JSON字符串
     */
    public boolean jsonStringCheckSignBySHA256(String jsonString, String signKeyName) throws Exception {
        if (jsonString == null || "".equals(jsonString)) {
            logger.error("AddSign.jsonStringCheckSignBySHA256: JSON字符串不能为空");
            throw new Exception("JSON字符串使用SHA256校验签名");
        }
        if (signKeyName == null || "".equals(signKeyName)) {
            logger.error("AddSign.jsonStringCheckSignBySHA256: 签名在JSON字符串时的KEY名不能为空");
            throw new Exception("JSON字符串使用SHA256校验签名");
        }

        Map<String, Object> map = JSONObject.parseObject(jsonString);

        String signFromJsonString = "";
        List<String> list = new ArrayList<String>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if(entry.getKey().equals("sign")){
                signFromJsonString = (String)entry.getValue();
                continue;
            }
            list.add(entry.getKey() + entry.getValue());
        }

        Collections.sort(list);

        String data = "";
        for (String subString : list) {
            data += subString;
        }

        String sign = SHA256.INSTANCE.getSHA256Str(data);

        return sign.equals(signFromJsonString);
    }
}
