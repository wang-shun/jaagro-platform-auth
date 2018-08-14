package com.jaagro.auth.web.config;

import com.google.common.collect.Lists;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ApiKey;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * @author tony
 * swagger 配置类
 */
@Configuration
@EnableSwagger2
public class SwaggerConfig {

    @Bean
    public Docket createRestApi() {
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.jaagro.auth.web.controller"))
                .paths(PathSelectors.any())
                .build().securitySchemes(Lists.newArrayList(apiKey()));
    }
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("认证 API")
                .description("Token获取方式请联系管理员")
                .termsOfServiceUrl("http://www.jaagro.com")
                .version("1.0")
                .build();
    }

    private ApiKey apiKey() {
        return new ApiKey("token", "token", "header");
    }

}
