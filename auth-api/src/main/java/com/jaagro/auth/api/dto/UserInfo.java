package com.jaagro.auth.api.dto;

import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serializable;

/**
 * @author tony
 */
@Data
@Accessors(chain = true)
public class UserInfo implements Serializable {

    private Long id;

    private String loginName;

    private String password;

    private String phoneNumber;

    private String salt;

    private Integer status;

    private String userType;
}
