/**
 * 2008-6-11
 */
package org.zlex.chapter07_3;

import static org.junit.Assert.assertEquals;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AES安全编码组件校验
 * 
 * @author 梁栋
 * @version 1.0
 */
public class AESCoderTest {
    /**
    * Logger for this class
    */
    private static final Logger logger = LoggerFactory.getLogger(AESCoderTest.class);

    /**
     * 测试
     * 
     * @throws Exception
     */
    @Test
    public final void test() throws Exception {
        String inputStr = "AES";
        byte[] inputData = inputStr.getBytes();
        System.err.println("原文:\t" + inputStr);

        // 初始化密钥
        byte[] key = AESCoder.initKey();
        logger.info("{}", key.length);
        System.err.println("密钥:\t" + Base64.encodeBase64String(key));

        // 加密
        inputData = AESCoder.encrypt(inputData, key);
        System.err.println("加密后:\t" + Base64.encodeBase64String(inputData));

        // 解密
        byte[] outputData = AESCoder.decrypt(inputData, key);

        String outputStr = new String(outputData);
        System.err.println("解密后:\t" + outputStr);

        // 校验
        assertEquals(inputStr, outputStr);

    }

    @Test
    public void test_001() {

        try {
            String input = "1470364368,BCSQOMKSQOMKSQOM,1000,36060730406";
            String key = "598c6bca44dc001f2b14d124b24f2da7";
            logger.info("{}",
                Base64.encodeBase64String(AESCoder.encrypt(input.getBytes(), key.getBytes())));

            logger.info("{}", Base64.encodeBase64String(encrypt(input, key)));
            logger.info("{}", Base64.encodeBase64String(encrypt2(input, key)));

            //  3AMPRP8BgQ0hxNzc21BhYJ7tSrnhHeBxydTqiw6662lOYwHBgdKu7Yz8wC0kDmeF
        } catch (Exception e) {
            logger.error("", e);
        }
    }

    public static byte[] encrypt(String content, String password) {
        // https://my.oschina.net/Jacker/blog/86383
        try {
            SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "AES");
            // logger.info("{}", keySpec.getEncoded().length);
            IvParameterSpec ivspec = new IvParameterSpec(password.substring(0, 16).getBytes());

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // logger.info("blockSize = {}", cipher.getBlockSize());

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivspec);
            byte[] encrypt = cipher.doFinal(content.getBytes());
            return encrypt;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }

        return null;
    }

    public static byte[] encrypt2(String content, String password) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, new SecureRandom(password.getBytes()));
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            logger.info("{}", enCodeFormat.length);
            logger.info("{}", Hex.toHexString(enCodeFormat));

            byte[] byteContent = content.getBytes("utf-8");

            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");

            Cipher cipher = Cipher.getInstance("AES");// 创建密码器  
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化  
            byte[] result = cipher.doFinal(byteContent);
            return result; // 加密  
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }

        return null;
    }

    @Test
    public void test_002() {
        String password = "pwd";
        try {
            KeyGenerator kgen_1 = KeyGenerator.getInstance("AES");
            kgen_1.init(128, new SecureRandom(password.getBytes()));

            KeyGenerator kgen_2 = KeyGenerator.getInstance("AES");
            kgen_2.init(128, new SecureRandom(password.getBytes()));

            byte[] encoded1 = kgen_1.generateKey().getEncoded();
            byte[] encoded2 = kgen_2.generateKey().getEncoded();
            logger.info("{}, {}", Hex.toHexString(encoded1), encoded1.length);
            logger.info("{}, {}", Hex.toHexString(encoded2), encoded2.length);
        } catch (NoSuchAlgorithmException e) {
            logger.error("", e);
        }
    }
}
