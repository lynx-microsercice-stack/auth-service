package lynx.auth.dto.request;

import lombok.Data;

@Data
public class RegisterUserRequest {
    private String username;
    private String password;
    private String email;
    private String firstName;
    private String lastName;

}
