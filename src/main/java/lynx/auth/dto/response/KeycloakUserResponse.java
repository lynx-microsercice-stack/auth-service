package lynx.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class KeycloakUserResponse {
    private String id;
    private String username;
    private String email;
    private boolean enabled;
    private boolean emailVerified;
    private List<String> requiredActions;
    private List<String> groups;
    private List<String> roles;
    
    @JsonProperty("createdTimestamp")
    private long createdAt;
    
    @JsonProperty("lastName")
    private String lastName;
    
    @JsonProperty("firstName")
    private String firstName;
} 