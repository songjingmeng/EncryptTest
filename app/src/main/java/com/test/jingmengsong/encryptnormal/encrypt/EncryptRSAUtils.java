package com.test.jingmengsong.encryptnormal.encrypt;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;

/**
 * 业务名：
 * 功能说明：RSA 加密
 *
 *         私钥的加解密 都较 公钥的加解密 耗时
 * 创建于：2018/6/6 on 15:42
 * 作者： jingmengsong
 * <p/>
 * 历史记录
 * 修改日期：
 * 修改人：
 * 修改内容：
 */
public class EncryptRSAUtils {


    //-------------------------------------- 加密填充方式 讲解  -------------------------------------------
    //关于加密填充方式：之前以为上面这些操作就能实现rsa加解密，以为万事大吉了，呵呵，这事还没完，悲剧还是发生了，Android这边加密过的数据，服务器端死活解密不了，
    // 原来android系统的RSA实现是"RSA/None/NoPadding"，而标准JDK实现是"RSA/None/PKCS1Padding" ，
    // 这造成了在android机上加密后无法在服务器上解密的原因，所以在实现的时候这个一定要注意。
    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";//加密填充方式


    //---------------------------------------------------------------------------------
    public static final String RSA = "RSA";// 非对称加密密钥算法
    public static final int DEFAULT_KEY_SIZE = 2048;//秘钥默认长度
    public static final byte[] DEFAULT_SPLIT = "#PART#".getBytes();    // 当要加密的内容超过bufferSize，则采用partSplit进行分块加密
    public static final int DEFAULT_BUFFERSIZE = (DEFAULT_KEY_SIZE / 8) - 11;// 当前秘钥支持加密的最大字节数

    //---------------------------------------  未进行分段加密解密  ------------------------------------------

    /**
     * 随机生成 RSA 密钥对
     *
     * @param keyLength 密钥长度， 范围 ：512 - 2048
     * @return 一般 1024
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(keyLength);
            return keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 私钥解密
     *
     * @param data       待解密数据
     * @param privateKey 密钥
     * @return 解密后的数据
     */
    public static byte[] decryptByPrivateKey(byte[] data, byte[] privateKey) throws Exception {
        //获取私钥
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PrivateKey keyPrivate = keyFactory.generatePrivate(keySpec);

        //用私钥进行解密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, keyPrivate);
        return cipher.doFinal(data);
    }

    /**
     * 公钥进行分段加密
     *
     * @param data
     * @param publicKey
     * @return
     */
    public static byte[] encryptByPublicKeyForSpilt(byte[] data, byte[] publicKey) throws Exception {

        //获取待加密 的字节数长度
        int dataLen = data.length;
        if (dataLen <= DEFAULT_BUFFERSIZE) {
            return encryptByPublicKey(data, publicKey);
        }

        ArrayList<Byte> allBytes = new ArrayList<>(2048);
        int bufIndex = 0;
        int subDataLoop = 0;
        byte[] buf = new byte[DEFAULT_BUFFERSIZE];
        for (int i = 0; i < dataLen; i++) {
            buf[bufIndex] = data[i];
            if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {

                subDataLoop++;
                if (subDataLoop != 1) {
                    for (byte b : DEFAULT_SPLIT) {
                        allBytes.add(b);
                    }
                }

                byte[] encryptBytes = encryptByPublicKey(buf, publicKey);
                for (byte b : encryptBytes) {
                    allBytes.add(b);
                }

                bufIndex = 0;
                if (i == dataLen - 1) {
                    buf = null;
                } else {
                    buf = new byte[Math.min(DEFAULT_BUFFERSIZE, dataLen - i - 1)];
                }
            }
        }

        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }

        return bytes;

    }

    /**
     * 用公钥对字符串进行加密
     * Cipher类为加密和解密提供密码功能
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey) throws Exception {
        //得到公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PublicKey keyPublic = kf.generatePublic(keySpec);
        //加密数据
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, keyPublic);
        return cipher.doFinal(data);
    }

    /**
     * 私钥进行加密
     *
     * @param data       待加密的数据
     * @param privateKey 密钥
     * @return 加密后的数据
     */
    public static byte[] encryptByPrivateKeyForSpilt(byte[] data, byte[] privateKey) throws Exception {
        int dataLen = data.length;
        if (dataLen <= DEFAULT_BUFFERSIZE) {
            return encryptByPrivateKey(data, privateKey);
        }

        ArrayList<Byte> allBytes = new ArrayList<>(2048);
        int bufIndex = 0;
        int subDataLoop = 0;
        byte[] buf = new byte[DEFAULT_BUFFERSIZE];
        for (int i = 0; i < dataLen; i++) {
            buf[bufIndex] = data[i];
            if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {
                subDataLoop++;
                if (subDataLoop != 1) {
                    for (byte b : DEFAULT_SPLIT) {
                        allBytes.add(b);
                    }
                }

                byte[] encryptBytes = encryptByPrivateKey(buf, privateKey);
                for (byte b : encryptBytes) {
                    allBytes.add(b);
                }

                bufIndex = 0;
                if (i == dataLen - 1) {
                    buf = null;
                } else {
                    buf = new byte[Math.min(DEFAULT_BUFFERSIZE, dataLen - i - 1)];
                }

            }
        }

        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }

        return bytes;

    }


    //------------------------------------------  实现分段加密 解密讲解  ----------------------------------------------

    //实现分段加密：搞定了填充方式之后又自信的认为万事大吉了，可是意外还是发生了，RSA非对称加密内容长度有限制，1024位key的最多只能加密117位数据，否则就会报错(javax.crypto.IllegalBlockSizeException: Data must not be longer than 117 bytes) ，
    // 　RSA 是常用的非对称加密算法。最近使用时却出现了“不正确的长度”的异常，研究发现是由于待加密的数据超长所致。
    // RSA 算法规定：待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：KeySize / 8 - 11），而加密后得到密文的字节数，正好是密钥的长度值除以 8（即：KeySize / 8）。

    /**
     * 用私钥对字符串进行加密
     * PKCS8EncodedKeySpec  类使用pkcs#8标准作为密钥规范管理的编码格式， 该类的命名由此得来
     * 需要通过这个类将文件中的字节数组读出并转化为密钥对象
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey) throws Exception {
        //得到私钥
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PrivateKey keyPrivate = keyFactory.generatePrivate(keySpec);

        //用私钥进行加密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, keyPrivate);
        return cipher.doFinal(data);
    }

    /**
     * 公钥分段解密
     *
     * @param data      待解密数据
     * @param publicKey 密钥
     * @return
     */
    public static byte[] decryptByPublicKeyForSpilt(byte[] data, byte[] publicKey) throws Exception {

        int spiltLen = DEFAULT_SPLIT.length;
        if (spiltLen <= 0) {
            return decryptByPublicKey(data, publicKey);
        }

        int dataLen = data.length;
        ArrayList<Byte> allBytes = new ArrayList<>(1024);
        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = data[i];
            boolean isMatchSpilt = false;
            if (i == dataLen - 1) {
                //到 data 的最后了
                byte[] part = new byte[dataLen - latestStartIndex];
                System.arraycopy(data, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPublicKey(part, publicKey);

                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + spiltLen;
                i = latestStartIndex - 1;
            } else if (bt == DEFAULT_SPLIT[0]) {
                //这个是以 spilt[0] 开头的
                if (spiltLen > 1) {
                    if (i + spiltLen < dataLen) {
                        //没有超出data的范围
                        for (int j = 1; j < spiltLen; j++) {
                            if (DEFAULT_SPLIT[j] != data[i + j]) {
                                break;
                            }

                            if (j == spiltLen - 1) {
                                //验证到split  的最后一位  ， 都没有break，则表明已经确认是split段
                                isMatchSpilt = true;
                            }

                        }
                    }
                } else {
                    //split 只有一位， 则已经匹配啦
                    isMatchSpilt = true;
                }
            }

            if (isMatchSpilt) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(data, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPublicKey(part, publicKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + spiltLen;
                i = latestStartIndex - 1;
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }


    /**
     * 公钥解密
     *
     * @param data      待解密数据
     * @param publicKey 密钥
     * @return 解密数据
     */
    public static byte[] decryptByPublicKey(byte[] data, byte[] publicKey) throws Exception {

        //得到公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PublicKey keyPublic = keyFactory.generatePublic(keySpec);

        //公钥解密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, keyPublic);
        return cipher.doFinal(data);

    }

    /**
     * 私钥分段解密
     *
     * @param encrypted       待解密数据
     * @param privateKey 密钥
     * @return
     */
    public static byte[] decryptByPrivateKeyForSpilt(byte[] encrypted, byte[] privateKey) throws Exception {

        int splitLen = DEFAULT_SPLIT.length;
        if (splitLen <= 0) {
            return decryptByPrivateKey(encrypted, privateKey);
        }
        //获取 待解密的数据长度
        int dataLen = encrypted.length;
        //创建一个容器来 承接 解密后的字节数据
        List<Byte> allBytes = new ArrayList<Byte>(1024);

        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = encrypted[i];
            boolean isMatchSplit = false;
            if (i == dataLen - 1) {
                // 到data的最后了
                byte[] part = new byte[dataLen - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPrivateKey(part, privateKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            } else if (bt == DEFAULT_SPLIT[0]) {
                // 这个是以split[0]开头
                if (splitLen > 1) {
                    if (i + splitLen < dataLen) {
                        // 没有超出data的范围
                        for (int j = 1; j < splitLen; j++) {
                            if (DEFAULT_SPLIT[j] != encrypted[i + j]) {
                                break;
                            }
                            if (j == splitLen - 1) {
                                // 验证到split的最后一位，都没有break，则表明已经确认是split段
                                isMatchSplit = true;
                            }
                        }
                    }
                } else {
                    // split只有一位，则已经匹配了
                    isMatchSplit = true;
                }
            }
            if (isMatchSplit) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPrivateKey(part, privateKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;

    }


}
