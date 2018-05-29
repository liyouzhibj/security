package com.rrtx.security.service;

import com.alibaba.fastjson.JSON;
import com.rrtx.security.domain.SecurityParams;
import com.rrtx.security.service.impl.SecurityImpl;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class SecurityTest {
    public static int num = 0;

    @Test
    public void securityTest() throws Exception {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(5, 10, 100000, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(5));

        for (int i = 0; i < 10; i++) {
            MyTask myTask = new MyTask(i);
            executor.execute(myTask);
            System.out.println("线程池中线程数目：" + executor.getPoolSize() + "，队列中等待执行的任务数目：" +
                    executor.getQueue().size() + "，已执行完的任务数目：" + executor.getCompletedTaskCount());
        }
        executor.shutdown();

        Thread.currentThread().sleep(100000);
        System.out.println("----------------------总次数-------------------------");
        System.out.println(num);
    }

    class MyTask implements Runnable {
        private int taskNum;

        public MyTask(int num) {
            this.taskNum = num;
        }

        public void run() {
            System.out.println("正在执行task " + taskNum);

            try {
                for (int i = 0; i < 1000; i++) {
                    num++;
                    ISecurity<String, SecurityParams> security = new SecurityImpl();
                    SecurityParams encryptParams = new SecurityParams();
                    encryptParams.setEncryptOrDecryptFlag(SecurityParams.ENCRYPT);
                    encryptParams.setRsaPublicKeyFromType(SecurityParams.RSA_PUBLICKEY_FROM_CERT);
                    encryptParams.setCertFilePath("../keys/openssl.crt");

                    Map<String, Object> parentMap = new HashMap<String, Object>();
                    Map<String, Object> subMap = new HashMap<String, Object>();
                    subMap.put("sub", "subTest");
                    parentMap.put("name", "zhangsan");
                    parentMap.put("email", "zhangsan@163.com");
                    parentMap.put("subJson", subMap);

                    String jsonString = JSON.toJSONString(parentMap);

                    encryptParams.setData(jsonString);

                    String encryptedData = security.security(encryptParams).replaceAll("%2B", "\\+");

                    SecurityParams decryptParams = new SecurityParams();
                    decryptParams.setEncryptOrDecryptFlag(SecurityParams.DECRYPTE);
                    decryptParams.setRsaPrivateKeyFromType(SecurityParams.RSA_PRIVATEKEY_FROM_PFX);
                    decryptParams.setPfxFilePath("../keys/opensslTest.pfx");
                    decryptParams.setPfxFileLoadPassword("111111");
                    decryptParams.setData(encryptedData);

                    String decryptedData = security.security(decryptParams);

//                    Assert.assertEquals(AddSign.INSTANCE.jsonStringAddSignBySHA256(jsonString), decryptedData);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            System.out.println("task " + taskNum + "执行完毕");
        }
    }
}
