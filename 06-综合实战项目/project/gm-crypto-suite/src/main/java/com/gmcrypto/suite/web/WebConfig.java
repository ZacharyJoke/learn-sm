package com.gmcrypto.suite.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.Duration;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Value("${gm.signature.timestamp-skew-seconds:300}")
    private long skewSeconds;

    @Bean
    AppKeyResolver appKeyResolver() {
        return new AppKeyResolver();
    }

    @Bean
    NonceStore nonceStore() {
        return new NonceStore();
    }

    @Bean
    CachedBodyFilter cachedBodyFilter() {
        return new CachedBodyFilter();
    }

    @Bean
    FilterRegistrationBean<CachedBodyFilter> cachedBodyFilterRegistration(CachedBodyFilter filter) {
        FilterRegistrationBean<CachedBodyFilter> registration = new FilterRegistrationBean<>(filter);
        registration.addUrlPatterns("/api/*");
        return registration;
    }

    @Bean
    SignVerifyInterceptor signVerifyInterceptor(AppKeyResolver appKeyResolver, NonceStore nonceStore) {
        return new SignVerifyInterceptor(appKeyResolver, nonceStore, Duration.ofSeconds(skewSeconds));
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(signVerifyInterceptor(appKeyResolver(), nonceStore()))
                .addPathPatterns("/api/signed/**");
    }
}
