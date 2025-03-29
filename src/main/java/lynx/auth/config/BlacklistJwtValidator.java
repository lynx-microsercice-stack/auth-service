package lynx.auth.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import lynx.auth.service.RedisService;

@Slf4j
@Component
@RequiredArgsConstructor
public class BlacklistJwtValidator implements OAuth2TokenValidator<Jwt> {

    private final RedisService redisService;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        try {
            String tokenValue = jwt.getTokenValue();
            // get user id
            String userId = jwt.getClaimAsString("sub");
            if (redisService.isTokenBlacklisted(tokenValue, userId)) {
                log.warn("Token is blacklisted: {}", tokenValue);
                return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Token is blacklisted", null)
                );
            }
            return OAuth2TokenValidatorResult.success();
        } catch (Exception e) {
            log.error("Error validating token: {}", e.getMessage());
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "Token validation failed", e.getMessage())
            );
        }
    }
} 