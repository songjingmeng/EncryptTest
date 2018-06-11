package com.test.jingmengsong.encryptnormal.encrypt;

import java.security.Provider;

/**
 * 业务名：
 * 功能说明：
 * 创建于：2018/6/8 on 15:13
 * 作者： jingmengsong
 * <p/>
 * 历史记录
 * 修改日期：
 * 修改人：
 * 修改内容：
 */
public  class CryptoProvider extends Provider{

    public CryptoProvider() {
        super("Crypto", 1.0, "HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature)");
        put("SecureRandom.SHA1PRNG",
                "org.apache.harmony.security.provider.crypto.SHA1PRNG_SecureRandomImpl");
        put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
    }

}
