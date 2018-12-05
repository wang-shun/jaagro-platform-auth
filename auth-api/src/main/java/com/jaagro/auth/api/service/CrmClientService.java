package com.jaagro.auth.api.service;

import com.jaagro.auth.api.dto.SocialDriverRegisterPurposeDto;
import com.jaagro.utils.BaseResponse;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author tony
 */
@FeignClient("crm")
public interface CrmClientService {

    /**
     * 判断司机在游客表中是否存在
     *
     * @param phoneNumber
     * @return
     */
    @GetMapping("/getByPhoneNumber")
    BaseResponse<SocialDriverRegisterPurposeDto> getByPhoneNumber(@RequestParam("phoneNumber") String phoneNumber);
}
