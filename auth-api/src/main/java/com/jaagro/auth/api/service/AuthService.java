package com.jaagro.auth.api.service;

import com.auth0.jwt.interfaces.Claim;
import com.jaagro.constant.UserInfo;

import java.util.Map;

/**
 * @author tony
 */
public interface AuthService {
    /**
     * 获取token
     * @param username 用户名
     * @param password 密码
     * @param userType 登录用户的类型
     * @return
     */
    Map<String, Object> createTokenByPassword(String username, String password, String userType);

    /**
     * 获取token
     * @param phoneNumber 手机号码
     * @param verificationCode 验证码
     * @param userType 登录用户的类型
     * @return token
     */
    Map<String, Object> createTokenByPhone(String phoneNumber, String verificationCode, String userType);

    /**
     * 注销token
     * @param token token
     */
    void invalidate(String token);

    /**
     * 刷新token
     * @param token token
     * @return refreshToken
     */
    String refresh(String token);

    /**
     * 延期token
     * @param token
     * @return
     */
    boolean postpone(String token);

    /**
     * 验证token
     * @param token
     * @return
     * @throws Exception
     */
    boolean verifyToken(String token);

    /**
     * 通过token获取user
     * @param token token
     * @return 封装后的userDto
     * @throws  Exception 解析token时有可能会抛出异常
     */
    UserInfo getUserByToken(String token) throws Exception;
}
