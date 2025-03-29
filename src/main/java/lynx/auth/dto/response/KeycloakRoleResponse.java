package lynx.auth.dto.response;

import lombok.Data;

@Data
public class KeycloakRoleResponse {
    private String id;
    private String name;
    private String description;
    private boolean composite;
    private boolean clientRole;
    private String containerId;
} 