package com.jaagro.auth.biz.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.jaagro.auth.api.constant.LoginType;
import com.jaagro.auth.api.constant.UserType;
import com.jaagro.auth.api.service.AuthService;
import com.jaagro.auth.api.service.UserClientService;
import com.jaagro.auth.api.service.VerificationCodeClientService;
import com.jaagro.constant.UserInfo;
import com.jaagro.utils.MD5Utils;
import com.jaagro.utils.ResponseStatusCode;
import com.jaagro.utils.ServiceResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 提供给feign调用，主要用于gateway层获取和验证token
 *
 * @author tony
 */
@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Autowired
    private UserClientService userClientService;
    @Autowired
    private VerificationCodeClientService verificationCodeClientService;
    @Autowired
    private StringRedisTemplate redisTemplate;

    /**
     * 秘钥
     */
    private static String SECRET_KEY;

    @Value("${jwt.secret.key}")
    public void setSecretKet(String secretKet) {
        SECRET_KEY = secretKet;
    }

    @Override
    public Map<String, Object> createTokenByPassword(String username, String password, String userType) {

        //判断user是否有效
        UserInfo user = userClientService.getUserInfo(username, userType, LoginType.LOGIN_NAME);
        if (user == null) {
            return ServiceResult.error(ResponseStatusCode.UNAUTHORIZED_ERROR.getCode(), username + " :用户名不存在");
        }
        String encodePassword = MD5Utils.encode(password, user.getSalt());
        if (!encodePassword.equals(user.getPassword())) {
            return ServiceResult.error(ResponseStatusCode.UNAUTHORIZED_ERROR.getCode(), "用户名或密码错误");
        }
        return createToken(user);
    }

    @Override
    public Map<String, Object> createTokenByPhone(String phoneNumber, String verificationCode, String userType) {
        UserInfo user = userClientService.getUserInfo(phoneNumber, userType, LoginType.PHONE_NUMBER);
        if (user == null) {
            return ServiceResult.error(ResponseStatusCode.UNAUTHORIZED_ERROR.getCode(), "手机号码未注册");
        }
        if (!verificationCodeClientService.existMessage(phoneNumber, verificationCode)) {
            return ServiceResult.error(ResponseStatusCode.UNAUTHORIZED_ERROR.getCode(), "验证码不正确");
        }
        return createToken(user);
    }

    private Map<String, Object> createToken(UserInfo user) {
        //签发时间
        Date iatDate = new Date();
        //token过期时间
//        Calendar nowTime = Calendar.getInstance();
//        nowTime.add(Calendar.MINUTE, 20);
//        Date expiresDate = nowTime.getTime();

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
//                    .withExpiresAt(expiresDate)
                    //设置签发时间
                    .withIssuedAt(iatDate)
                    //加密
                    .sign(Algorithm.HMAC256(SECRET_KEY));
            if (UserType.DRIVER.equals(user.getUserType()) || UserType.CUSTOMER.equals(user.getUserType())) {
                redisTemplate.opsForValue().set(token, user.getId().toString(), 31, TimeUnit.DAYS);
            } else {
                redisTemplate.opsForValue().set(token, user.getId().toString(), 7, TimeUnit.DAYS);
            }

        } catch (Exception e) {
            e.printStackTrace();
            log.error(e + ": 令牌生成失败");
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
    public boolean postpone(String token) {
        UserInfo userInfo = null;
        //解析token
        try {
            userInfo = this.getUserByToken(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        //有部分请求是不需要token的,故过滤掉这部分
        if (StringUtils.isEmpty(token)) {
            return false;
        }
        if (!StringUtils.isEmpty(redisTemplate.opsForValue().get(token))) {
            if(UserType.DRIVER.equals(userInfo.getUserType())){
                redisTemplate.expire(token, 31, TimeUnit.DAYS);
            } else {
                redisTemplate.expire(token, 7, TimeUnit.DAYS);
            }

            return true;
        }
        log.warn(token + " :该token无效，延期失败！");
        return false;
    }

    @Override
    public boolean verifyToken(String token) {
        String flg = null;
        if (!StringUtils.isEmpty(token)) {
            flg = redisTemplate.opsForValue().get(token);
        }
        if (!StringUtils.isEmpty(flg)) {
            return true;
        }
        log.warn(token + ":该token无效。userId: " + flg);
        return false;
    }

    @Override
    public UserInfo getUserByToken(String token) throws Exception {
        if (StringUtils.isEmpty(redisTemplate.opsForValue().get(token))) {
            log.warn(token + ": token无效");
            return null;
        }
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET_KEY)).build();
        DecodedJWT jwt;
        try {
            jwt = verifier.verify(token);
        } catch (Exception e) {
            e.printStackTrace();
            log.warn(e + ": token解析出错");
            return null;
        }
        String userIdStr = jwt.getClaim("user").asString();
        String userType = jwt.getClaim("userType").asString();
        //需要查出user对象封装并返回
        UserInfo userInfo = new UserInfo();
        //通过user来判断token是否有效
        if (!StringUtils.isEmpty(userIdStr)) {
            Integer userId = Integer.valueOf(userIdStr);
            userInfo = userClientService.getUserInfo(userId, userType, LoginType.ID);
        }
        return userInfo;
    }
}
