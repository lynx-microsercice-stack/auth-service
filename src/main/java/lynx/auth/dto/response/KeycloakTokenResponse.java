package lynx.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
public class KeycloakTokenResponse {
    @JsonProperty("access_token")
    private String access_token;
    
    @JsonProperty("refresh_token")
    private String refresh_token;
    
    @JsonProperty("expires_in")
    private Integer expires_in;
    
    @JsonProperty("refresh_expires_in")
    private Integer refresh_expires_in;
    
    @JsonProperty("token_type")
    private String token_type;
    
    @JsonProperty("scope")
    private String scope;
} 