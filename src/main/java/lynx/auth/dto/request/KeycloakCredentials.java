package lynx.auth.dto.request;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class KeycloakCredentials {
    private String type;
    private String value;
    private boolean temporary;
}
