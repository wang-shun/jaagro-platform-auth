package com.jaagro.auth.api.service;

import com.jaagro.auth.api.dto.SocialDriverRegisterPurposeDto;
import com.jaagro.utils.BaseResponse;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author tony
 */
@FeignClient("crm")
public interface CrmClientService {

    /**
     * 根据手机号获取游客身份司机
     *
     * @param phoneNumber
     * @return
     */
    @GetMapping("/getByPhoneNumber")
    BaseResponse<SocialDriverRegisterPurposeDto> getByPhoneNumber(@RequestParam("phoneNumber") String phoneNumber);

    /**
     * 根据id获取游客身份司机
     *
     * @param id
     * @return
     */
    @GetMapping("/socialDriverRegisterPurpose/{id}")
    BaseResponse<SocialDriverRegisterPurposeDto> getSocialDriverRegisterPurposeDtoById(@PathVariable(value = "id") Integer id);
}
