/**
 * LS_Demon Org.
 * Copyright (c) 2005-2016 All Rights Reserved.
 */
package com.test;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author lisong
 * @version $Id: Sha512Test.java, v 0.1 2016年1月10日 下午3:48:29 lisong Exp $
 */
public class Sha512Test {
    /**
    * Logger for this class
    */
    private static final Logger logger = LoggerFactory.getLogger(Sha512Test.class);

    @Test
    public void test_aa() {
        try {
            String charsetName = "utf-8";

            String pwd = "Witon@123qwe";
            String sal = "wrpcmyb6";

            byte[] bs = DigestUtils.sha512((pwd + sal).getBytes(charsetName));
            logger.info("{}", Hex.toHexString(bs));
            logger.info("{}", new String(Base64.encodeBase64(bs), charsetName));

            byte[] bbb = DigestUtils.sha512((sal + pwd).getBytes(charsetName));
            logger.info("{}", Hex.toHexString(bbb));
            logger.info("{}", new String(Base64.encodeBase64(bbb), charsetName));
        } catch (Exception e) {
            logger.error("", e);
        }
    }

    @Test
    public void test_md5() {
        try {
            String charsetName = "utf-8";

            String pwd = "manifold";
            String sal = "6C1PNDsk";

            byte[] bs = DigestUtils.md5((pwd + sal).getBytes(charsetName));
            logger.info("{}", Hex.toHexString(bs));
            logger.info("{}", new String(Base64.encodeBase64(bs), charsetName));

            byte[] bbb = DigestUtils.md5((sal + pwd).getBytes(charsetName));
            logger.info("{}", Hex.toHexString(bbb));
            logger.info("{}", new String(Base64.encodeBase64(bbb), charsetName));
        } catch (Exception e) {
            logger.error("", e);
        }
    }
}
