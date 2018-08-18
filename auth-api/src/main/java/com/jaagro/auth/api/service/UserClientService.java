package com.jaagro.auth.api.service;

import com.jaagro.auth.api.dto.UserInfo;
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
     * 通过username获取userInfo
     * @param username 用户名
     * @param userType 账号类型
     * @return
     */
    @GetMapping("/getByUsername")
    UserInfo getByName(@RequestParam("username") String username, @RequestParam("userType") String userType);

    /**
     * 通过手机号获取userInfo
     * @param phoneNumber 手机号码
     * @param userType 账号类型
     * @return
     */
    @GetMapping("/getByPhoneNumber")
    UserInfo getByPhone(@RequestParam("phoneNumber") String phoneNumber, @RequestParam("userType") String userType);

    /**
     * 通过id获取userDto
     * @param id 用户id
     * @param userType 账号类型
     * @return
     */
    @GetMapping("/getById")
    UserInfo getById(@RequestParam("id") Long id, @RequestParam("userType") String userType);
}
