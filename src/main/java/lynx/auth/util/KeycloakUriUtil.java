package lynx.auth.util;

import lombok.experimental.UtilityClass;

@UtilityClass
public class KeycloakUriUtil {
    private static final String MASTER_REALM = "master";
    private static final String TARGET_REALM = "lynx-realm";

    public static String getMasterRealmUrl(String issuerUri) {
        return issuerUri.replace("/realms/" + TARGET_REALM, "/realms/" + MASTER_REALM);
    }

    public static String getBaseUrl(String issuerUri) {
        return issuerUri.replace("/realms/" + TARGET_REALM, "");
    }

    public static String getAdminTokenEndpoint(String issuerUri) {
        return getMasterRealmUrl(issuerUri) + "/protocol/openid-connect/token";
    }

    public static String getAdminUsersEndpoint(String issuerUri) {
        return getBaseUrl(issuerUri) + "/admin/realms/" + TARGET_REALM + "/users";
    }

    public static String getAdminUserEndpoint(String issuerUri, String userId) {
        return getBaseUrl(issuerUri) + "/admin/realms/" + TARGET_REALM + "/users/" + userId;
    }

    public static String getAdminUserRolesEndpoint(String issuerUri, String userId) {
        return getBaseUrl(issuerUri) + "/admin/realms/" + TARGET_REALM + "/users/" + userId + "/role-mappings/realm";
    }

    public static String getAdminRolesEndpoint(String issuerUri) {
        return getBaseUrl(issuerUri) + "/admin/realms/" + TARGET_REALM + "/roles";
    }

    public static String getAdminRoleEndpoint(String issuerUri, String roleName) {
        return getBaseUrl(issuerUri) + "/admin/realms/" + TARGET_REALM + "/roles/" + roleName;
    }

    public static String getAdminUserLogoutEndpoint(String issuerUri, String userId) {
        return getBaseUrl(issuerUri) + "/admin/realms/" + TARGET_REALM + "/users/" + userId + "/logout";
    }

    public static String getTokenEndpoint(String issuerUri) {
        return issuerUri + "/protocol/openid-connect/token";
    }
} 