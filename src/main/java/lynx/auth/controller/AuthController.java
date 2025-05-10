package lynx.auth.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lynx.auth.common.BaseResponse;
import lynx.auth.dto.request.ClientTokenRequest;
import lynx.auth.dto.request.LoginRequest;
import lynx.auth.dto.request.RegisterRequest;
import lynx.auth.dto.response.AuthResponse;
import lynx.auth.dto.response.KeycloakUserResponse;
import lynx.auth.service.KeycloakService;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {

    private final KeycloakService keycloakService;

    /**
     *  ========== REGISTER ==========
     */
    @Operation(
        summary = "Register a new user",
        description = "Creates a new user account in Keycloak with the specified role"
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User successfully registered", 
            content = @Content(schema = @Schema(implementation = String.class))),
        @ApiResponse(responseCode = "400", description = "Invalid input data"),
        @ApiResponse(responseCode = "409", description = "User with the provided email already exists"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/register")
    public ResponseEntity<BaseResponse<String>> register(
        @Parameter(description = "User registration details", required = true)
        @Valid @RequestBody RegisterRequest request
    ) {
        String userId = keycloakService.createUser(
                request.getUsername(),
                request.getPassword(),
                request.getEmail(),
                request.getFirstName(),
                request.getLastName(),
                request.getRole()
        );
        return ResponseEntity.ok(BaseResponse.success(userId));
    }

    /**
     *  ========== LOGIN ==========
     */
    @Operation(
        summary = "User login",
        description = "Authenticates a user and returns an access token"
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Login successful", 
            content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid credentials"),
        @ApiResponse(responseCode = "401", description = "Authentication failed"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
        @Parameter(description = "User login credentials", required = true)
        @Valid @RequestBody LoginRequest request
    ) {
        String accessToken = keycloakService.getToken(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(new AuthResponse(
                accessToken,
                null, // Refresh token not implemented yet
                "Bearer",
                300, // 5 minutes
                "openid profile email"
        ));
    }

    /**
     *  ========== LOGOUT ==========
     */
    @Operation(
        summary = "User logout",
        description = "Logs out the current user and invalidates their token"
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Logout successful"),
        @ApiResponse(responseCode = "401", description = "User not authenticated"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        keycloakService.logout();
        return ResponseEntity.ok().build();
    }

    /**
     *  ========== LOGOUT ALL ==========
     */
    @Operation(
        summary = "Logout from all sessions",
        description = "Logs out the user from all active sessions and invalidates all their tokens"
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Logout from all sessions successful"),
        @ApiResponse(responseCode = "401", description = "User not authenticated"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll() {
        keycloakService.logoutAll();
        return ResponseEntity.ok().build();
    }

    @Operation(
        summary = "Validate token",
        description = "Validates the provided JWT token"
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Token is valid", 
            content = @Content(schema = @Schema(implementation = String.class))),
        @ApiResponse(responseCode = "401", description = "Invalid or expired token"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })

    /**
     *  ========== VALIDATE TOKEN ==========
     */
    @PostMapping("/validate")
    public ResponseEntity<String> validate(
        @Parameter(description = "HTTP request containing the Authorization header")
        HttpServletRequest request
    ) {
        String authHeader = request.getHeader("Authorization");
        String token = authHeader.substring(7); // Remove "Bearer " prefix
        return ResponseEntity.ok(token);
    }

    /**
     *  ========== GET CLIENT TOKEN ==========
     */
    @PostMapping("/token/client")
    public ResponseEntity<BaseResponse<Object>> getClientToken(@RequestBody ClientTokenRequest request) {
        String token = keycloakService.getClientToken(request.getClientId(), request.getClientSecret());
        
        return ResponseEntity.ok(BaseResponse.success(token));
    }

    /**
     *  ========== GET CURRENT USER ID ==========
     */
    @Operation(
        summary = "Get current user ID",
        description = "Returns the ID of the currently authenticated user"
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User ID retrieved successfully", 
            content = @Content(schema = @Schema(implementation = String.class))),
        @ApiResponse(responseCode = "401", description = "User not authenticated"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @Parameter(description = "Keycloak ID to fetch", required = true, schema = @Schema(type = "string"))
    @GetMapping("/user/{keycloakId}")
    public ResponseEntity<BaseResponse<KeycloakUserResponse>> fetchUser(@PathVariable("keycloakId") String keycloakId) {
        KeycloakUserResponse user = keycloakService.getUserId(keycloakId);
        return ResponseEntity.ok(BaseResponse.success(user));
    }

    /**
     *  ========== FETCH ALL USERS ==========
     */
    @Operation(
        summary = "Fetch all users",
        description = "Fetches all users from Keycloak"
    )
    @GetMapping("/users")
    public ResponseEntity<BaseResponse<List<KeycloakUserResponse>>> fetchUsers() {
        var users = keycloakService.getAllUsers();
        return ResponseEntity.ok(BaseResponse.success(users));
    }

    @Operation(
        summary = "Delete user",
        description = "Deletes a user from Keycloak"
    )   
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User deleted successfully"),
        @ApiResponse(responseCode = "401", description = "User not authenticated"),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @Parameter(description = "Keycloak ID to delete", required = true, schema = @Schema(type = "string"))
    @DeleteMapping("/delete/user/{keycloakId}")
    public ResponseEntity<BaseResponse<String>> deleteUser(@PathVariable("keycloakId") String keycloakId) {
        keycloakService.deleteUser(keycloakId);
        return ResponseEntity.ok(BaseResponse.success("User deleted successfully"));
    }
} 