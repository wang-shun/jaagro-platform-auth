package com.jaagro.auth.web.controller;

import com.jaagro.auth.api.exception.AuthorizationException;
import com.jaagro.auth.api.service.AuthService;
import com.jaagro.auth.api.service.UserClientService;
import com.jaagro.auth.api.service.VerificationCodeClientService;
import com.jaagro.constant.UserInfo;
import com.jaagro.utils.BaseResponse;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

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
     *
     * @param username
     * @param password
     * @return
     */
    @PostMapping("/token")
    public BaseResponse getTokenByPassword(@RequestParam("username") String username,
                                           @RequestParam("password") String password,
                                           @RequestParam("userType") @ApiParam(value = "共三个类型：customer、employee、driver", required = true) String userType) {

        String token = authService.createTokenByPassword(username, password, userType);
        return BaseResponse.successInstance((Object) token);
    }

    /**
     * 通过短信验证码获取token
     *
     * @param phoneNumber
     * @param verificationCode
     * @return
     */
    @GetMapping("/token")
    public BaseResponse getTokenByPhone(@RequestParam("phoneNumber") String phoneNumber,
                                        @RequestParam("verificationCode") String verificationCode,
                                        @RequestParam("userType") @ApiParam(value = "共三个类型：customer、employee、driver", required = true) String userType,
                                        @RequestParam(value = "wxId", required = false) String wxId) {
        String token = authService.createTokenByPhone(phoneNumber, verificationCode, userType, wxId);
        return BaseResponse.successInstance((Object) token);
    }

    /**
     * 通过wxId获取token
     * @param wxId
     * @return
     */
    @PostMapping("/getTokenByWxId/{wxId}")
    public BaseResponse getTokenByWxId(@PathVariable("wxId") String wxId) {
        return BaseResponse.successInstance(authService.getTokenByWxId(wxId));
    }

    /**
     * 提供给gateway层的zuulFilter做验证使用，所以不使用baseResponse对象封装
     *
     * @param token
     * @return
     */
    @PostMapping("/verifyToken")
    public boolean verifyToken(String token) {
        return authService.verifyToken(token);
    }

    /**
     * 提供给其他业务微服务获取当前user使用
     *
     * @param token
     * @return
     */
    @PostMapping("/getUserByToken")
    public UserInfo getUserByToken(String token) {

        UserInfo userInfo = null;
        try {
            userInfo = authService.getUserByToken(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return userInfo;
    }

    /**
     * 延期token，用户每次请求api 都将调用此方法延长token在redis中的有效期（3天）
     *
     * @param token
     * @return
     */
    @PostMapping("/postponeToken")
    public boolean postponeToken(@RequestParam("token") String token) {
        return authService.postpone(token);
    }

    /**
     * 提供给其他服务
     *
     * @param id
     * @param userType
     * @return
     */
    @PostMapping("getUserById")
    public UserInfo getUserInfoById(@RequestParam("id") Integer id, @RequestParam("userType") String userType) {
        return userClientService.getUserInfo(id, userType, "id");
    }
}
