package org.skyline.jwt.services;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.skyline.jwt.security.JwtUtils;
import org.skyline.jwt.services.interfaces.ITokenBlacklistService;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService implements ITokenBlacklistService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtUtils jwtUtils;

    @Override
    public void addToBlacklist(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);
        Date expiry = jwtUtils.extractExpiration(token);

        long expiration = expiry.getTime() - System.currentTimeMillis();
        redisTemplate.opsForValue().set(token, "blacklisted", expiration, TimeUnit.MILLISECONDS);
    }

    @Override
    public Boolean isBlacklisted(String token) {
        return redisTemplate.hasKey(token);
    }
}
