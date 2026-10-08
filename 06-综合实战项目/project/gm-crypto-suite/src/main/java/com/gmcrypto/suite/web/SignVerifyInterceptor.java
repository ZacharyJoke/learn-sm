package com.gmcrypto.suite.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gmcrypto.suite.codec.Codec;
import com.gmcrypto.suite.sm2.Sm2Support;
import com.gmcrypto.suite.sm3.Sm3Support;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.HandlerInterceptor;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

public class SignVerifyInterceptor implements HandlerInterceptor {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final AppKeyResolver appKeyResolver;
    private final NonceStore nonceStore;
    private final Duration maxSkew;

    public SignVerifyInterceptor(AppKeyResolver appKeyResolver, NonceStore nonceStore, Duration maxSkew) {
        this.appKeyResolver = appKeyResolver;
        this.nonceStore = nonceStore;
        this.maxSkew = maxSkew;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String appId = request.getHeader(SignHeaders.APP_ID);
        String timestamp = request.getHeader(SignHeaders.TIMESTAMP);
        String nonce = request.getHeader(SignHeaders.NONCE);
        String signatureHex = request.getHeader(SignHeaders.SIGNATURE);

        if (appId == null || timestamp == null || nonce == null || signatureHex == null) {
            return reject(response, HttpStatus.BAD_REQUEST, "缺少签名头");
        }

        Instant requestTime;
        try {
            requestTime = Instant.ofEpochMilli(Long.parseLong(timestamp));
        } catch (NumberFormatException e) {
            return reject(response, HttpStatus.BAD_REQUEST, "时间戳格式错误");
        }
        if (Duration.between(requestTime, Instant.now()).abs().compareTo(maxSkew) > 0) {
            return reject(response, HttpStatus.BAD_REQUEST, "请求已过期");
        }

        byte[] body = request instanceof CachedBodyHttpServletRequest cached ? cached.body() : new byte[0];
        String bodyDigest = Codec.toHex(Sm3Support.digest(body));
        String signingContent = String.join("\n", appId, timestamp, nonce, request.getMethod(),
                request.getRequestURI(), bodyDigest);

        boolean valid;
        try {
            valid = Sm2Support.verify(appKeyResolver.resolve(appId),
                    Codec.utf8(signingContent), Codec.fromHex(signatureHex));
        } catch (RuntimeException e) {
            return reject(response, HttpStatus.UNAUTHORIZED, "签名无效");
        }
        if (!valid) {
            return reject(response, HttpStatus.UNAUTHORIZED, "签名校验失败");
        }

        if (!nonceStore.registerIfAbsent(nonce, maxSkew.multipliedBy(2))) {
            return reject(response, HttpStatus.CONFLICT, "重复请求");
        }
        return true;
    }

    private boolean reject(HttpServletResponse response, HttpStatus status, String message) throws Exception {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        OBJECT_MAPPER.writeValue(response.getWriter(), Map.of("error", message));
        return false;
    }
}
