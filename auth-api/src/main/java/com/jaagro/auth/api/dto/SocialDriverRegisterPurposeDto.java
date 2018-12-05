package com.jaagro.auth.api.dto;

import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serializable;
import java.util.Date;

/**
 * @author yj
 * @since 2018/12/5
 */
@Data
@Accessors(chain = true)
public class SocialDriverRegisterPurposeDto implements Serializable {
    /**
     * 社会司机注册意向表id
     */
    private Integer id;

    /**
     * 真实姓名
     */
    private String name;

    /**
     * 手机号
     */
    private String phoneNumber;

    /**
     * 司机类型(1-个人,2-企业)
     */
    private Integer driverType;

    /**
     * 车辆数量
     */
    private Integer truckQuantity;

    /**
     * 所属城市
     */
    private String city;

    /**
     * 详细地址
     */
    private String detailAddress;

    /**
     * 上传时间
     */
    private Date uploadTime;

    /**
     * 备注
     */
    private String notes;
}
