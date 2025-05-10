package lynx.auth.service;

import java.util.List;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lynx.auth.dto.request.KeycloakCredentials;
import lynx.auth.dto.request.KeycloakRegisterRequest;
import lynx.auth.dto.response.KeycloakRoleResponse;
import lynx.auth.dto.response.KeycloakTokenResponse;
import lynx.auth.dto.response.KeycloakUserResponse;
import lynx.auth.util.KeycloakUriUtil;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakService {

    private final RestTemplate restTemplate;
    private final RedisService redisService;
    private final JwtDecoder jwtDecoder;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issuerUri;

    @Value("${keycloak.admin.username}")
    private String adminUsername;

    @Value("${keycloak.admin.password}")
    private String adminPassword;

    public String createUser(String username, String password, String email, String firstName, String lastName, String role) {
        String adminToken = getAdminToken();
        String usersEndpoint = KeycloakUriUtil.getAdminUsersEndpoint(issuerUri);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        var user = KeycloakRegisterRequest.builder()
                .username(username)
                .credentials(List.of(KeycloakCredentials.builder().type("password").value(password).build()))
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .enabled(true)
                .build();

        HttpEntity<KeycloakRegisterRequest> request = new HttpEntity<>(user, headers);
        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(usersEndpoint, request, Void.class);
            String userId = Objects.requireNonNull(response.getHeaders().get("Location")).getFirst().split("/users/")[1];

            try {
                assignRole(userId, role);
                return userId;
            } catch (Exception e) {
                // If role assignment fails, delete the created user
                deleteUser(userId);
                throw new RuntimeException("Failed to assign role to user. User creation rolled back.", e);
            }
        } catch (HttpClientErrorException.Conflict ex) {
            log.error("User creation failed: User with email {} already exists", email);
            throw ex; // Let the global exception handler handle it
        }
    }

    private String getAdminToken() {
        String tokenEndpoint = KeycloakUriUtil.getAdminTokenEndpoint(issuerUri);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(createAdminTokenParams(), headers);

        ResponseEntity<KeycloakTokenResponse> response = restTemplate.postForEntity(
                tokenEndpoint, request, KeycloakTokenResponse.class);
        var responseBody = response.getBody();
        if (responseBody == null) {
            throw new RuntimeException("Failed to obtain admin token");
        }
        return responseBody.getAccess_token();
    }

    private MultiValueMap<String, String> createAdminTokenParams() {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", "admin-cli");
        map.add("client_secret", clientSecret);
        map.add("username", adminUsername);
        map.add("password", adminPassword);
        return map;
    }

    private void assignRole(String userId, String roleName) {
        String adminToken = getAdminToken();
        String rolesEndpoint = KeycloakUriUtil.getAdminUserRolesEndpoint(issuerUri, userId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        String roleEndpoint = KeycloakUriUtil.getAdminRoleEndpoint(issuerUri, roleName);
        ResponseEntity<KeycloakRoleResponse> roleResponse = restTemplate.exchange(
                roleEndpoint, HttpMethod.GET, new HttpEntity<>(headers), KeycloakRoleResponse.class);

        KeycloakRoleResponse role = roleResponse.getBody();
        if (role == null) {
            throw new RuntimeException("Role not found: " + roleName);
        }

        HttpEntity<List<KeycloakRoleResponse>> request = new HttpEntity<>(List.of(role), headers);
        restTemplate.postForEntity(rolesEndpoint, request, Void.class);
    }

    public void deleteUser(String userId) {
        String adminToken = getAdminToken();
        String deleteEndpoint = KeycloakUriUtil.getAdminUserEndpoint(issuerUri, userId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);
        restTemplate.exchange(deleteEndpoint, HttpMethod.DELETE, request, Void.class);
    }

    public String getToken(String username, String password) {
        String tokenEndpoint = KeycloakUriUtil.getTokenEndpoint(issuerUri);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("username", username);
        map.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        try {
            ResponseEntity<KeycloakTokenResponse> response = restTemplate.postForEntity(
                    tokenEndpoint, request, KeycloakTokenResponse.class);
            
            if (response.getBody() == null) {
                log.error("Failed to get token: Response body is null");
                throw new BadCredentialsException("Failed to get token: Response body is null");
            }

            // Track the token for the user
            return  Objects.requireNonNull(response.getBody()).getAccess_token();
        } catch (BadCredentialsException | RestClientException e) {
            log.error("Failed to get token: {}", e.getMessage());
            throw new BadCredentialsException("Failed to get token: " + e.getMessage());
        }
    }

    private String getUserIdFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getSubject();
        } catch (JwtException e) {
            log.error("Failed to decode token to get user ID: {}", e.getMessage());
            throw new RuntimeException("Failed to decode token", e);
        }
    }

    public Jwt getAccessToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || !(authentication instanceof JwtAuthenticationToken jwtAuthentication)) {
            throw new BadCredentialsException("User is not authenticated");
        }

        return jwtAuthentication.getToken();
    }

    public KeycloakUserResponse getUserId(String keycloakId) {
        try {
            KeycloakUserResponse user = getUserById(keycloakId);
            if (user == null) {
                throw new IllegalStateException("User not found with ID: " + keycloakId);
            }
            return user;
        } catch (IllegalStateException e) {
            throw new IllegalStateException("Cannot get user ID: User is not authenticated", e);
        }
    }

    public String getUsername() {
        try {
            return getAccessToken().getClaimAsString("preferred_username");
        } catch (IllegalStateException e) {
            throw new IllegalStateException("Cannot get username: User is not authenticated", e);
        }
    }

    public List<String> getRoles() {
        try {
            return getAccessToken().getClaimAsStringList("roles");
        } catch (IllegalStateException e) {
            throw new IllegalStateException("Cannot get roles: User is not authenticated", e);
        }
    }

    public boolean hasRole(String role) {
        return getRoles().contains(role);
    }

    public boolean isValidToken() {
        try {
            JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
            return authentication != null && authentication.isAuthenticated();
        } catch (Exception e) {
            return false;
        }
    }

    public void logout() {
        try {
            Jwt token = getAccessToken();
            String tokenString = token.getTokenValue();
            String userId = token.getSubject();
            
            // Blacklist current token
            redisService.blacklistToken(tokenString, userId);
            
            SecurityContextHolder.clearContext();
            log.info("User logged out successfully and token blacklisted");
        } catch (Exception e) {
            log.error("Error during logout: {}", e.getMessage());
            throw new RuntimeException("Failed to logout", e);
        }
    }

    public void logoutAll() {
        try {
            Jwt token = getAccessToken();
            String tokenString = token.getTokenValue();
            String userId = token.getSubject();
            
            // Get admin token for Keycloak operations
            String adminToken = getAdminToken();
            
            // Remove all sessions from Keycloak
            String logoutEndpoint = KeycloakUriUtil.getAdminUserLogoutEndpoint(issuerUri, userId);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(adminToken);
            
            HttpEntity<Void> request = new HttpEntity<>(headers);
            restTemplate.postForEntity(logoutEndpoint, request, Void.class);
            
            // Blacklist current token
            redisService.blacklistToken(tokenString, userId);
            
            SecurityContextHolder.clearContext();
            log.info("User logged out from all sessions successfully");
        } catch (Exception e) {
            log.error("Error during logout all: {}", e.getMessage());
            throw new RuntimeException("Failed to logout from all sessions", e);
        }
    }

    public KeycloakUserResponse getUserById(String userId) {
        String adminToken = getAdminToken();
        String userEndpoint = KeycloakUriUtil.getAdminUserEndpoint(issuerUri, userId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<KeycloakUserResponse> response = restTemplate.exchange(
                userEndpoint, HttpMethod.GET, request, KeycloakUserResponse.class);

        return response.getBody();
    }

    public List<KeycloakUserResponse> getAllUsers() {
        String adminToken = getAdminToken();
        String usersEndpoint = KeycloakUriUtil.getAdminUsersEndpoint(issuerUri);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<List<KeycloakUserResponse>> response = restTemplate.exchange(
                usersEndpoint, HttpMethod.GET, request, 
                new ParameterizedTypeReference<List<KeycloakUserResponse>>() {});

        return response.getBody();
    }

    public List<KeycloakUserResponse> searchUsers(String searchQuery) {
        String adminToken = getAdminToken();
        String usersEndpoint = KeycloakUriUtil.getAdminUsersEndpoint(issuerUri) + "?search=" + searchQuery;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<List<KeycloakUserResponse>> response = restTemplate.exchange(
                usersEndpoint, HttpMethod.GET, request, 
                new ParameterizedTypeReference<List<KeycloakUserResponse>>() {});

        return response.getBody();
    }

    /**
     * 
     * @param clientId
     * @param clientSecret
     * @return access token for the client
     */
    public String getClientToken(final String clientId, final String clientSecret) {
        String tokenEndpoint = KeycloakUriUtil.getTokenEndpoint(issuerUri);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "client_credentials");
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<KeycloakTokenResponse> response = restTemplate.postForEntity(
                tokenEndpoint, request, KeycloakTokenResponse.class);

        return Objects.requireNonNull(response.getBody()).getAccess_token();
    }
} 