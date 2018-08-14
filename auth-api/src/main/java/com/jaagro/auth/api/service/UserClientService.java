package com.jaagro.auth.api.service;

import com.jaagro.auth.api.dto.UserDto;
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
     * 通过username获取userDto
     * @param username username
     * @return
     */
    @GetMapping("/getByUsername")
    UserDto getByName(@RequestParam("username") String username);

    /**
     * 通过手机号获取userDto
     * @param phoneNumber
     * @return
     */
    @GetMapping("/getByPhoneNumber")
    UserDto getByPhone(@RequestParam("phoneNumber") String phoneNumber);

    /**
     * 通过id获取userDto
     * @param id
     * @return
     */
    @GetMapping("/getById")
    UserDto getById(@RequestParam("id") Long id);
}
