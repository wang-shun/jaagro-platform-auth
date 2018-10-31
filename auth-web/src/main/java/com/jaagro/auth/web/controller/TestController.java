package com.jaagro.auth.web.controller;

import com.jaagro.constant.UserInfo;
import com.jaagro.utils.BaseResponse;
import org.springframework.beans.BeanUtils;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author tony
 */
@RestController
public class TestController {

    @GetMapping("/test22")
    public BaseResponse test(){
        UserInfo userInfo = null;
        get(userInfo);
        return BaseResponse.successInstance(userInfo);
    }

    private UserInfo get(UserInfo userInfo) {
        Assert.notNull(userInfo, "userInfo must not be null");
        return userInfo;
    }
}
