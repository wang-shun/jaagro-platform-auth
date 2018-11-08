package com.jaagro.auth.web.controller;

import com.jaagro.auth.api.service.AuthService;
import com.jaagro.auth.api.service.UserClientService;
import com.jaagro.auth.api.service.VerificationCodeClientService;
import com.jaagro.auth.web.config.HttpClientUtil;
import com.jaagro.auth.web.vo.LoginParamVo;
import com.jaagro.constant.UserInfo;
import com.jaagro.utils.BaseResponse;
import com.jaagro.utils.ResponseStatusCode;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * @author tony
 */
@Slf4j
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
     * @param param
     * @return
     */
    @PostMapping("/token")
    public BaseResponse getTokenByPassword(@RequestBody LoginParamVo param) {

        if(StringUtils.isEmpty(param.getUsername()) || StringUtils.isEmpty(param.getPassword()) || StringUtils.isEmpty(param.getUserType())){
            return BaseResponse.errorInstance(ResponseStatusCode.QUERY_DATA_ERROR.getCode(), "缺少参数");
        }
        String token = authService.createTokenByPassword(param.getUsername(), param.getPassword(), param.getUserType());
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
     *
     * @param wxId
     * @return
     */
    @GetMapping("/getTokenByWxId/{wxId}")
    public BaseResponse getTokenByWxId(@PathVariable("wxId") String wxId) {
        return BaseResponse.successInstance((Object) authService.getTokenByWxId(wxId));
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
     * 延期token，用户每次请求api 都将调用此方法延长token在redis中的有效期
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

    /**
     * 获取微信id
     *
     * @param appId
     * @param secret
     * @param jsCode
     * @return
     */
    @GetMapping("/getWxCode")
    public String getWxCode(String appId, String secret, String jsCode) {
        String url = "https://api.weixin.qq.com/sns/jscode2session";
        Map<String, String> param = new HashMap<>(16);
        param.put("appid", appId);
        param.put("secret", secret);
        param.put("js_code", jsCode);
        param.put("grant_type", "authorization_code");
        String result = HttpClientUtil.doGet(url, param);
        log.debug("微信接口返回：" + result);
        return result;
    }
}
