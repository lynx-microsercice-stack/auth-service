package lynx.auth.service;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisService {
    private final RedisTemplate<String, String> redisTemplate;
    private static final String TOKEN_BLACKLIST_PREFIX = "blacklist:token";
    private static final long TOKEN_BLACKLIST_TTL = 24; // hours

    public void blacklistToken(String token, String userId) {
        String key = getKey(userId, token);
        redisTemplate.opsForValue().set(key, "blacklisted", TOKEN_BLACKLIST_TTL, TimeUnit.HOURS);
    }

    private String getKey(String userId, String token) {
        return String.format("%s:%s:%s", TOKEN_BLACKLIST_PREFIX, token, userId);
    }

    public boolean isTokenBlacklisted(String token, String userId) {
        String key = getKey(userId, token);
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
} 