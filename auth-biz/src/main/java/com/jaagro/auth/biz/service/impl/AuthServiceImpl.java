package com.jaagro.auth.biz.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.jaagro.auth.api.constant.LoginType;
import com.jaagro.auth.api.constant.UserType;
import com.jaagro.auth.api.exception.AuthorizationException;
import com.jaagro.auth.api.service.AuthService;
import com.jaagro.auth.api.service.UserClientService;
import com.jaagro.auth.api.service.VerificationCodeClientService;
import com.jaagro.constant.UserInfo;
import com.jaagro.utils.MD5Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;
import java.sql.Time;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 授权中心核心代码，提供token的生成、验证、延时、解析功能
 * token生成组件使用的是auth0提供的开源组件
 * token的格式为JWT，此授权中心只使用auto0生成JWT格式的token，token持久化到rides，验证也是匹配redis中是否存在而非标准的JWT验证token规则
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
    public String createTokenByPassword(String username, String password, String userType) {
        //判断user是否有效
        UserInfo user = userClientService.getUserInfo(username, userType, LoginType.LOGIN_NAME);
        if (null == user) {
            throw new AuthorizationException(username + " :用户不存在");
        }
        String encodePassword = MD5Utils.encode(password, user.getSalt());
        if (!encodePassword.equals(user.getPassword())) {
            throw new AuthorizationException("用户名或密码不正确");
        }
        return createToken(user, null);
    }

    @Override
    public String createTokenByPhone(String phoneNumber, String verificationCode, String userType, String wxId) {
        UserInfo user = userClientService.getUserInfo(phoneNumber, userType, LoginType.PHONE_NUMBER);
        if (null == user) {
            throw new AuthorizationException(phoneNumber + ": 手机号未注册");
        }
        if (!verificationCodeClientService.existMessage(phoneNumber, verificationCode)) {
            throw new AuthorizationException("验证码不正确");
        }
        return createToken(user, wxId);
    }

    @Override
    public String getTokenByWxId(String wxId) {
        String tokenData = redisTemplate.opsForValue().get(wxId);
        if (StringUtils.isEmpty(tokenData)) {
            throw new AuthorizationException("weiXin id must not be null");
        }
        return tokenData;
    }

    private String createToken(UserInfo user, String wxId) throws AuthorizationException {

        Assert.notNull(user, "user must not be null");

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
            boolean flg = UserType.DRIVER.equals(user.getUserType()) || UserType.CUSTOMER.equals(user.getUserType());
            if (flg) {
                redisTemplate.opsForValue().set(token, user.getId().toString() + "," + (StringUtils.isEmpty(wxId) ? "" : wxId), 31, TimeUnit.DAYS);
                redisTemplate.opsForValue().set(user.getId().toString(), token, 31, TimeUnit.DAYS);
            } else {
                redisTemplate.opsForValue().set(token, user.getId().toString() + "," + (StringUtils.isEmpty(wxId) ? "" : wxId), 7, TimeUnit.DAYS);
                redisTemplate.opsForValue().set(user.getId().toString(), token, 7, TimeUnit.DAYS);
            }
            //微信小程序多插入一条以wxId为Key的记录
            Boolean flag = UserType.CUSTOMER.equals(user.getUserType()) || UserType.LOAD_SITE.equals(user.getUserType()) || UserType.UNLOAD_SITE.equals(user.getUserType()) || UserType.VISITOR_CUSTOMER_P.equals(user.getUserType()) || UserType.VISITOR_CUSTOMER_U.equals(user.getUserType());
            if (flag && !StringUtils.isEmpty(wxId)) {
                log.debug("O createToken: current weiXin openId : {}", wxId);
                redisTemplate.opsForValue().set(wxId, token, 31, TimeUnit.DAYS);
            }
        } catch (Exception e) {
            throw new AuthorizationException("token creation failed");
        }
        return token;
    }

    @Override
    public void invalidate(String token, String userId) {
        if (StringUtils.isEmpty(token) && StringUtils.isEmpty(userId)) {
            throw new NullPointerException("token or userId cannot all be empty");
        }
        if (StringUtils.isEmpty(token) && !StringUtils.isEmpty(userId)) {
            token = redisTemplate.opsForValue().get(userId);
            if (StringUtils.isEmpty(token)) {
                throw new NullPointerException(userId + " :userId not logged in");
            }
        }
        String tokenValue = redisTemplate.opsForValue().get(token);
        String[] vs = tokenValue.split(",");
        if (StringUtils.isEmpty(userId)) {
            userId = vs[0];
        }
        //vs的长度如果大于1说明token中存在wxId
        String wxId = "";
        if (vs.length > 1) {
            wxId = vs[1];
        }
        redisTemplate.delete(token);
        redisTemplate.delete(wxId);
        redisTemplate.delete(userId);
    }

    @Override
    public String refresh(String token) {
        return null;
    }

    @Override
    public boolean postpone(String token) {
        String tokenValue = redisTemplate.opsForValue().get(token);
        //有部分请求是不需要token或传入一个无效token，故过滤掉这部分
        if (StringUtils.isEmpty(token) || StringUtils.isEmpty(tokenValue)) {
            return false;
        }
        UserInfo userInfo = this.getUserByToken(token);
        String wxId = tokenValue.substring(tokenValue.indexOf(",") + 1);
        if (!StringUtils.isEmpty(tokenValue) && null != userInfo) {
            boolean flg = UserType.DRIVER.equals(userInfo.getUserType()) || UserType.CUSTOMER.equals(userInfo.getUserType());
            if (flg) {
                redisTemplate.expire(token, 31, TimeUnit.DAYS);
                redisTemplate.expire(userInfo.getId().toString(), 31, TimeUnit.DAYS);
            } else {
                redisTemplate.expire(token, 7, TimeUnit.DAYS);
                redisTemplate.expire(userInfo.getId().toString(), 7, TimeUnit.DAYS);
            }
            //微信小程序专属
            if (UserType.CUSTOMER.equals(userInfo.getUserType()) && !StringUtils.isEmpty(wxId)) {
                redisTemplate.expire(wxId, 31, TimeUnit.DAYS);
            }
            return true;
        }
        log.warn("O postpone: token postpone failed: {}", token);
        return false;
    }

    @Override
    public boolean verifyToken(String token) {
        boolean flg = false;
        if (!StringUtils.isEmpty(token)) {
            flg = !StringUtils.isEmpty(redisTemplate.opsForValue().get(token));
        }
        return flg;
    }

    @Override
    public UserInfo getUserByToken(String token) {
        if (StringUtils.isEmpty(redisTemplate.opsForValue().get(token))) {
            log.info("O getUserByToken: Token does not exist: {}", token);
            return null;
        }
        JWTVerifier verifier;
        try {
            verifier = JWT.require(Algorithm.HMAC256(SECRET_KEY)).build();
        } catch (UnsupportedEncodingException e) {
            log.error("R getUserByToken: ", e);
            return null;
        }
        DecodedJWT jwt;
        jwt = verifier.verify(token);
        String userIdStr = jwt.getClaim("user").asString();
        String userType = jwt.getClaim("userType").asString();
        //需要查出user对象封装并返回
        UserInfo userInfo = new UserInfo();
        if (!StringUtils.isEmpty(userIdStr)) {
            Integer userId = Integer.valueOf(userIdStr);
            userInfo = userClientService.getUserInfo(userId, userType, LoginType.ID);
        }
        return userInfo;
    }
}
