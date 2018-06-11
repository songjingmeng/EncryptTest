package com.test.jingmengsong.encryptnormal;

import java.io.Serializable;

/**
 * 业务名：
 * 功能说明：
 * 创建于：2018/6/8 on 09:59
 * 作者： jingmengsong
 * <p/>
 * 历史记录
 * 修改日期：
 * 修改人：
 * 修改内容：
 */
public class Person implements Serializable{

    private int age;
    private String name;

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getName() {
        return name == null ? "" : name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
