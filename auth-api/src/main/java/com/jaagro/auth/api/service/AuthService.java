package com.jaagro.auth.api.service;

import com.auth0.jwt.interfaces.Claim;
import com.jaagro.auth.api.dto.UserDto;

import java.util.Map;

/**
 * @author tony
 */
public interface AuthService {
    /**
     * 获取token
     * @param username
     * @param password
     * @return
     */
    Map<String, Object> createTokenByPassword(String username, String password);

    /**
     * 获取token
     * @param phoneNumber 手机号码
     * @param verificationCode 验证码
     * @return token
     */
    Map<String, Object> createTokenByPhone(String phoneNumber, String verificationCode);

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
     * 验证token
     * @param token
     * @return
     * @throws Exception
     */
    Map<String, Claim> verifyToken(String token) throws Exception;

    /**
     * 通过token获取user
     * @param token token
     * @return 封装后的userDto
     * @throws  Exception 解析token时有可能会抛出异常
     */
    UserDto getUserByToken(String token) throws Exception;
}
