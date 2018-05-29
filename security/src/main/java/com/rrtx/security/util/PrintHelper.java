package com.rrtx.security.util;

public enum PrintHelper {
    INSTANCE;

    public void printHelper(String headerName, String printData) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            stringBuilder.append("-");
        }
        stringBuilder.append(headerName);
        for (int i = stringBuilder.length(); i < 60; i++) {
            stringBuilder.append("-");
        }

        String header = stringBuilder.toString();

        System.out.println(header);
        int n = 0;
        for (n = 0; n < printData.length() / 60; n++) {
            System.out.println(printData.substring(n * 60, n * 60 + 60));
        }
        System.out.println(printData.substring(n * 60, printData.length()));
        System.out.println(header);
    }

    public void printHelper(String headerName, byte[] printDataBytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            stringBuilder.append("-");
        }
        stringBuilder.append(headerName);
        for (int i = stringBuilder.length(); i < 60; i++) {
            stringBuilder.append("-");
        }

        String header = stringBuilder.toString();

        System.out.println(header);
        String printData = new String(printDataBytes);
        int n = 0;
        for (n = 0; n < printData.length() / 60; n++) {
            System.out.println(printData.substring(n * 60, n * 60 + 60));
        }
        System.out.println(printData.substring(n * 60, printData.length()));
        System.out.println(header);
    }
}
