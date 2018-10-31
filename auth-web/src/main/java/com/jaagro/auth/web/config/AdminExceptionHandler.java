package com.jaagro.auth.web.config;

import com.jaagro.auth.api.exception.AuthorizationException;
import com.jaagro.utils.BaseResponse;
import com.jaagro.utils.ResponseStatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author tony
 */
@ControllerAdvice
public class AdminExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(AdminExceptionHandler.class);

    @ResponseBody
    @ExceptionHandler(value = Exception.class)
    public BaseResponse javaExceptionHandler(Exception e) {
        log.error(e.getMessage(), e);
        return BaseResponse.errorInstance(e.getMessage());
    }

    @ResponseBody
    @ExceptionHandler(value = AuthorizationException.class)
    public BaseResponse authorizationExceptionHandler(Exception e) {
        log.error(e.getMessage(), e);
        return BaseResponse.errorInstance(ResponseStatusCode.UNAUTHORIZED_ERROR.getCode(), e.getMessage());
    }
}
