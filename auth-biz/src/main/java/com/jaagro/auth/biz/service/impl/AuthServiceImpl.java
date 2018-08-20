package com.jaagro.auth.biz.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.jaagro.auth.api.constant.LoginType;
import com.jaagro.auth.api.dto.UserInfo;
import com.jaagro.auth.api.exception.AuthorizationException;
import com.jaagro.auth.api.service.AuthService;
import com.jaagro.auth.api.service.UserClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import utils.MD5Utils;
import utils.ResponseStatusCode;
import utils.ServiceResult;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 提供给feign调用，主要用于gateway层获取和验证token
 * @author tony
 */
@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserClientService userClientService;

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    /**
     * 秘钥
     */
    private static String SECRET_KET;

    @Value("${jwt.secret.key}")
    public void setSecretKet(String secretKet) {
        SECRET_KET = secretKet;
    }

    @Override
    public Map<String, Object> createTokenByPassword(String username, String password, String userType) {

        //判断user是否有效
        UserInfo user = userClientService.getUserInfo(username, userType, LoginType.LOGIN_NAME);
        String encodePassword = MD5Utils.encode(password, user.getSalt());
        if(!encodePassword.equals(user.getPassword())){
            return ServiceResult.error(ResponseStatusCode.UNAUTHORIZED_ERROR.getCode(), "用户名或密码错误");
        }
        return createToken(user);
    }

    @Override
    public Map<String, Object> createTokenByPhone(String phoneNumber, String verificationCode, String userType) {
        UserInfo user = userClientService.getUserInfo(phoneNumber, userType, LoginType.PHONE_NUMBER);
        if(user == null){
            return ServiceResult.error(ResponseStatusCode.UNAUTHORIZED_ERROR.getCode(), "手机号码未注册");
        }
        return createToken(user);
    }

    private Map<String, Object> createToken(UserInfo user){
        //签发时间
        Date iatDate = new Date();

        //token过期时间
        Calendar nowTime = Calendar.getInstance();
        nowTime.add(Calendar.MINUTE, 60 * 12);
        Date expiresDate = nowTime.getTime();

        Map<String, Object> map = new HashMap<>(16);
        map.put("alg", "HS256");
        map.put("type", "JWT");

        String token = null;
        try {
            token = JWT.create()
                    //header
                    .withHeader(map)
                    //payload：用于存放有效信息的地方
                    .withClaim("user", user.getId().toString())
                    .withClaim("userType", user.getUserType())
                    //设置过期时间，过期时间必须大于签发时间
                    .withExpiresAt(expiresDate)
                    //设置签发时间
                    .withIssuedAt(iatDate)
                    //加密
                    .sign(Algorithm.HMAC256(SECRET_KET));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return ServiceResult.error("令牌生成失败，请重新操作");
        }
        return ServiceResult.toResult(token);
    }

    @Override
    public void invalidate(String token) {

    }

    @Override
    public String refresh(String token) {
        return null;
    }

    @Override
    public Map<String, Claim> verifyToken(String token) throws Exception {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET_KET)).build();
        DecodedJWT jwt = null;
        try {
            jwt = verifier.verify(token);
        }catch (Exception e){
            throw new AuthorizationException("令牌无效或已过期");
        }
        return jwt.getClaims();
    }

    /**
     * 通过token获取user
     * @param token token
     * @return 封装后的userDto
     */
    @Override
    public UserInfo getUserByToken(String token) throws Exception {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET_KET)).build();
        DecodedJWT jwt = null;
        try {
            jwt = verifier.verify(token);
        }catch (Exception e){
            e.printStackTrace();
            return new UserInfo().setId(-9999L).setLoginName("当前令牌无效");
        }
        String userIdStr = jwt.getClaim("user").asString();
        String userType = jwt.getClaim("userType").asString();
        //需要查出user对象封装并返回
        UserInfo userInfo = new UserInfo();
        //目前框架的逻辑，通过user来判断token是否有效
        if(!StringUtils.isEmpty(userIdStr)){
            Long userId = Long.valueOf(userIdStr);
            userInfo = userClientService.getUserInfo(userId, userType, LoginType.ID);
        }

        //用于兼容老系统的token,后期重构完成后可删除
        String username = jwt.getClaim("user_name").asString();
        if(!StringUtils.isEmpty(username)){
            userInfo.setLoginName(username);
        }
        return userInfo;
    }

}
