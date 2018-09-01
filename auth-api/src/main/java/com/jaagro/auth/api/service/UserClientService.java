package com.jaagro.auth.api.service;

import com.jaagro.constant.UserInfo;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 用于验证请求生成token的请求是否有效
 * @author tony
 */
@FeignClient(value = "user")
public interface UserClientService {

    /**
     * 获取userInfo
     * @param key 查询user的参数: 可以是loginName, phoneNumber, id 任意一种
     * @param userType 类型有三种：customer， employee， driver
     * @param loginType 类型有三种： loginName, phoneNumber, id
     * @return userInfo对象
     */
    @GetMapping("/getUserInfo")
    UserInfo getUserInfo(@RequestParam("key") Object key, @RequestParam("userType") String userType, @RequestParam("loginType") String loginType);
}
