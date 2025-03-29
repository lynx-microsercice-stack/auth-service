package lynx.auth.dto.request;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class KeycloakRegisterRequest {
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private boolean enabled;
    private List<KeycloakCredentials> credentials;
}

