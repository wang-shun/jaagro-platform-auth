package com.jaagro.auth.web.controller;

import com.auth0.jwt.interfaces.Claim;
import com.jaagro.auth.api.constant.LoginType;
import com.jaagro.auth.api.dto.UserInfo;
import com.jaagro.auth.api.service.AuthService;
import com.jaagro.auth.api.service.VerificationCodeClientService;
import com.jaagro.auth.api.service.UserClientService;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import utils.BaseResponse;

import java.util.Map;

/**
 * @author tony
 */
@RestController
public class AuthController {

    @Autowired
    private AuthService authService;
    @Autowired
    private UserClientService userClientService;
    @Autowired
    private VerificationCodeClientService verificationCodeClientService;

    /**
     * 通过用户名密码获取token
     * @param username
     * @param password
     * @return
     */
    @PostMapping("/token")
    public BaseResponse getTokenByPassword(@RequestParam("username") String username,
                                           @RequestParam("password") String password,
                                           @RequestParam("userType") @ApiParam(value = "共三个类型：customer、employee、driver", required = true) String userType) {
        if(userClientService.getUserInfo(username, userType, LoginType.LOGIN_NAME) == null){
            return BaseResponse.errorInstance(username + " :当前用户不存在");
        }
        Map<String, Object> map = authService.createTokenByPassword(username, password, userType);
        return BaseResponse.service(map);
    }

    /**
     * 通过短信验证码获取token
     * @param phoneNumber
     * @param verificationCode
     * @return
     */
    @GetMapping("/token")
    public BaseResponse getTokenByPhone(@RequestParam("phoneNumber") String phoneNumber,
                                        @RequestParam("verificationCode") String verificationCode,
                                        @RequestParam("userType") @ApiParam(value = "共三个类型：customer、employee、driver", required = true) String userType){
        UserInfo user = userClientService.getUserInfo(phoneNumber, userType, LoginType.PHONE_NUMBER);
        if(user == null){
            return BaseResponse.errorInstance(phoneNumber + " :未注册");
        }
        if(!verificationCodeClientService.existMessage(phoneNumber, verificationCode)){
            return BaseResponse.errorInstance("验证码不正确");
        }

        Map<String, Object> map = authService.createTokenByPhone(phoneNumber, verificationCode, userType);
        return BaseResponse.service(map);
    }

    /**
     * 提供给gateway层的zuulFilter做验证使用，所以不使用baseResponse对象封装
     * @param token
     * @return
     */
    @PostMapping("/verifyToken")
    public boolean verifyToken(String token){
        try {
            authService.verifyToken(token);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    @PostMapping("/decodeToken")
    public Map<String, Claim> decodeToken(String token){
        Map<String, Claim> map = null;
        try {
            map = authService.verifyToken(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return map;
    }

    /**
     * 提供给其他业务微服务获取当前user使用
     * @param token
     * @return
     */
    @PostMapping("/getUserByToken")
    public UserInfo getUserByToken(String token){
        UserInfo userInfo = null;
        try {
            userInfo = authService.getUserByToken(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return userInfo;
    }
}
