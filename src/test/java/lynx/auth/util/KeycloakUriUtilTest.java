package lynx.auth.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakUriUtilTest {

    private static final String BASE_URL = "http://localhost:8088";
    private static final String ISSUER_URI = BASE_URL + "/realms/lynx-realm";

    @Nested
    @DisplayName("Base URL and Master Realm URL Tests")
    class BaseUrlTests {
        @Test
        @DisplayName("Should correctly extract base URL")
        void shouldGetBaseUrl() {
            String expected = BASE_URL;
            String actual = KeycloakUriUtil.getBaseUrl(ISSUER_URI);
            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("Should correctly get master realm URL")
        void shouldGetMasterRealmUrl() {
            String expected = BASE_URL + "/realms/master";
            String actual = KeycloakUriUtil.getMasterRealmUrl(ISSUER_URI);
            assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("Admin Token Endpoint Tests")
    class AdminTokenEndpointTests {
        @Test
        @DisplayName("Should correctly construct admin token endpoint")
        void shouldGetAdminTokenEndpoint() {
            String expected = BASE_URL + "/realms/master/protocol/openid-connect/token";
            String actual = KeycloakUriUtil.getAdminTokenEndpoint(ISSUER_URI);
            assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("Admin User Endpoint Tests")
    class AdminUserEndpointTests {
        @Test
        @DisplayName("Should correctly construct admin users endpoint")
        void shouldGetAdminUsersEndpoint() {
            String expected = BASE_URL + "/admin/realms/lynx-realm/users";
            String actual = KeycloakUriUtil.getAdminUsersEndpoint(ISSUER_URI);
            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("Should correctly construct admin user endpoint with user ID")
        void shouldGetAdminUserEndpoint() {
            String userId = "123";
            String expected = BASE_URL + "/admin/realms/lynx-realm/users/" + userId;
            String actual = KeycloakUriUtil.getAdminUserEndpoint(ISSUER_URI, userId);
            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("Should correctly construct admin user roles endpoint")
        void shouldGetAdminUserRolesEndpoint() {
            String userId = "123";
            String expected = BASE_URL + "/admin/realms/lynx-realm/users/" + userId + "/role-mappings/realm";
            String actual = KeycloakUriUtil.getAdminUserRolesEndpoint(ISSUER_URI, userId);
            assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("Admin Role Endpoint Tests")
    class AdminRoleEndpointTests {
        @Test
        @DisplayName("Should correctly construct admin roles endpoint")
        void shouldGetAdminRolesEndpoint() {
            String expected = BASE_URL + "/admin/realms/lynx-realm/roles";
            String actual = KeycloakUriUtil.getAdminRolesEndpoint(ISSUER_URI);
            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("Should correctly construct admin role endpoint with role name")
        void shouldGetAdminRoleEndpoint() {
            String roleName = "admin";
            String expected = BASE_URL + "/admin/realms/lynx-realm/roles/" + roleName;
            String actual = KeycloakUriUtil.getAdminRoleEndpoint(ISSUER_URI, roleName);
            assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("User Logout Endpoint Tests")
    class UserLogoutEndpointTests {
        @Test
        @DisplayName("Should correctly construct admin user logout endpoint")
        void shouldGetAdminUserLogoutEndpoint() {
            String userId = "123";
            String expected = BASE_URL + "/admin/realms/lynx-realm/users/" + userId + "/logout";
            String actual = KeycloakUriUtil.getAdminUserLogoutEndpoint(ISSUER_URI, userId);
            assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("Token Endpoint Tests")
    class TokenEndpointTests {
        @Test
        @DisplayName("Should correctly construct token endpoint")
        void shouldGetTokenEndpoint() {
            String expected = ISSUER_URI + "/protocol/openid-connect/token";
            String actual = KeycloakUriUtil.getTokenEndpoint(ISSUER_URI);
            assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {
        @Test
        @DisplayName("Should handle URLs with different ports")
        void shouldHandleDifferentPorts() {
            String customIssuerUri = "http://localhost:8089/realms/lynx-realm";
            String expected = "http://localhost:8089/realms/master/protocol/openid-connect/token";
            String actual = KeycloakUriUtil.getAdminTokenEndpoint(customIssuerUri);
            assertEquals(expected, actual);
        }
    }
} 