package com.test.jingmengsong.encryptnormal;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.alibaba.fastjson.JSON;
import com.test.jingmengsong.encryptnormal.encrypt.EncryptAESUtils;
import com.test.jingmengsong.encryptnormal.encrypt.EncryptDESUtils;
import com.test.jingmengsong.encryptnormal.encrypt.EncryptMD5Utils;
import com.test.jingmengsong.encryptnormal.encrypt.EncryptRSAUtils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = "TAG";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //准备100条数据进行测试
        ArrayList<Person> personList = new ArrayList<>();
        int testMaxCount = 100; // 测试的最大数据条数
        //添加测试数据
        for (int i = 0; i < testMaxCount; i++) {
            Person person = new Person();
            person.setAge(i);
            person.setName("测试加解密数据啦" + String.valueOf(i));
            personList.add(person);

        }


        String jsonStr = JSON.toJSONString(personList);

        Log.i(TAG, "加密之前的数据 " + jsonStr);
        Log.i(TAG, "加密之前的数据 长度: " + jsonStr.length());

        //生成密钥对
        KeyPair keyPair = EncryptRSAUtils.generateRSAKeyPair(EncryptRSAUtils.DEFAULT_KEY_SIZE);
        //公钥
        PublicKey publicKey = keyPair.getPublic();
        //私钥
        PrivateKey privateKey = keyPair.getPrivate();


        //公钥加密
        long start = System.currentTimeMillis();
        try {
            byte[] encryptBytes = EncryptRSAUtils.encryptByPublicKeyForSpilt(jsonStr.getBytes(), publicKey.getEncoded());
            long end = System.currentTimeMillis();
            Log.i(TAG, "公钥加密 耗时 cost time----------> " + (end - start));
            String strBase64 = Base64.encodeToString(encryptBytes, Base64.DEFAULT);
            Log.i(TAG, " 加密后json 数据 " + strBase64);
            Log.i(TAG, " 加密后 json 数据长度 " + strBase64.length());

            //私钥解密
            start = System.currentTimeMillis();
            byte[] decryptBytes = EncryptRSAUtils.decryptByPrivateKeyForSpilt(Base64.decode(strBase64, Base64.DEFAULT), privateKey.getEncoded());
            String decryStr = new String(decryptBytes);
            end = System.currentTimeMillis();
            Log.e("MainActivity", "私钥解密耗时 cost time---->" + (end - start));
            Log.e("MainActivity", "解密后json数据 --1-->" + decryStr);

            //私钥 加密
            start = System.currentTimeMillis();
            encryptBytes = EncryptRSAUtils.encryptByPrivateKeyForSpilt(jsonStr.getBytes(), privateKey.getEncoded());
            end = System.currentTimeMillis();
            Log.e("MainActivity", "私钥加密密耗时 cost time---->" + (end - start));
            strBase64 = Base64.encodeToString(encryptBytes, Base64.DEFAULT);
            Log.e("MainActivity", "加密后json数据 --2-->" + strBase64);
            Log.e("MainActivity", "加密后json数据长度 --2-->" + strBase64.length());

            //公钥 解密
            start = System.currentTimeMillis();
            decryptBytes = EncryptRSAUtils.decryptByPublicKeyForSpilt(Base64.decode(strBase64, Base64.DEFAULT), publicKey.getEncoded());
            decryStr = new String(decryptBytes);
            end = System.currentTimeMillis();
            Log.e("MainActivity", "公钥解密耗时 cost time---->" + (end - start));
            Log.e("MainActivity", "解密后json数据 --2-->" + decryStr);
        } catch (Exception e) {
            e.printStackTrace();
        }


        //----------------------------------  AES  加密测试 -------------------------------
        //生成动态 key
        String secrectKey = EncryptAESUtils.generateKey();
        //AES 加密
        start = System.currentTimeMillis();
        String encryptAES = EncryptAESUtils.encrypt(secrectKey, jsonStr);
        long end = System.currentTimeMillis();
        Log.e("MainActivity", "AES 生成的密钥 ---->" + secrectKey);
        Log.e("MainActivity", "AES加密耗时 cost time---->" + (end - start));
        Log.e("MainActivity", "AES加密后json数据 ---->" + encryptAES);
        Log.e("MainActivity", "AES加密后json数据长度 ---->" + encryptAES.length());

        //AES 解密
        start = System.currentTimeMillis();
        String decryptAES = EncryptAESUtils.decrypt(secrectKey, encryptAES);
        end = System.currentTimeMillis();
        Log.e("MainActivity", "AES解密耗时 cost time---->" + (end - start));
        Log.e("MainActivity", "AES解密后json数据 ---->" + decryptAES);


        //----------------------------------  DES 加密测试 ---------------------------------
        //生成动态key
        String key = EncryptDESUtils.generateKey();
        //AES 加密
        start = System.currentTimeMillis();
        String encodeDES = EncryptDESUtils.encode(key, jsonStr);
        end  = System.currentTimeMillis();
        Log.e("MainActivity", "DES 生成的密钥 ---->" + secrectKey);
        Log.e("MainActivity", "DES加密耗时 cost time---->" + (end - start));
        Log.e("MainActivity", "DES加密后json数据 ---->" + encodeDES);
        Log.e("MainActivity", "DES加密后json数据长度 ---->" + encodeDES.length());

        //AES 解密
        start = System.currentTimeMillis();
        String decryptDES = EncryptDESUtils.decode(key, encodeDES);
        end = System.currentTimeMillis();
        Log.e("MainActivity", "DES解密耗时 cost time---->" + (end - start));
        Log.e("MainActivity", "DES解密后json数据 ---->" + decryptDES);


        //------------------------------------ Md5 加密测试 ---------------------------------
        String md5Str = EncryptMD5Utils.md5("12345asdfg");
        Log.i(TAG, "密码 MD5 加密后 成为: "+md5Str);


    }
}
