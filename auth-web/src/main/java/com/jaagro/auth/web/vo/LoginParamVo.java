package com.jaagro.auth.web.vo;

import lombok.Data;

import java.io.Serializable;

/**
 * @author tony
 */
@Data
public class LoginParamVo implements Serializable {

    /**
     * 用户名
     */
    private String username;

    /**
     * 密码
     */
    private String password;

    /**
     * 用户类型： customer、employee、driver
     */
    private String userType;
}
