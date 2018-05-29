package com.rrtx.security.util;

public enum IntToStrFormat {
    INSTANCE;

    public String intToStrFormatBy0(int formatLength, int num) {
        StringBuffer formatLengthTemp = new StringBuffer();
        for (int i = 0; i < formatLength; i++) {
            formatLengthTemp.append("0");
        }
        String numStr = String.valueOf(num);
        String result = formatLengthTemp.substring(0, formatLength - numStr.length()) + numStr;

        return result;
    }
}
