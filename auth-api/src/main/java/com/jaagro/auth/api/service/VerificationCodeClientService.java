package com.jaagro.auth.api.service;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author tony
 */
@FeignClient("component")
public interface VerificationCodeClientService {

    /**
     * 验证验证码是否存正确
     * @param phoneNumber
     * @param verificationCode
     * @return
     */
    @PostMapping("/existMessage")
    boolean existMessage(@RequestParam("phoneNumber") String phoneNumber, @RequestParam("verificationCode") String verificationCode);
}
