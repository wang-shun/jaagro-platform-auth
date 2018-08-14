package com.jaagro.auth.api.dto;

import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serializable;
import java.util.Date;

/**
 * @author tony
 */
@Data
@Accessors(chain = true)
public class UserDto implements Serializable {

    private Long id;

    private String username;

    private String password;

    private String phoneNumber;

    private String salt;

    private String name;

    private String avatar;

    private Integer customerId;

    private Date birthday;

    private String email;

    private Integer userStatus;

    private Date createTime;

    private Date modifyTime;
}
