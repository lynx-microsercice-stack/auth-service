package lynx.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lynx.auth.dto.response.AuthResponse;
import lynx.auth.dto.request.LoginRequest;
import lynx.auth.dto.request.RegisterRequest;
import lynx.auth.service.KeycloakService;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {

    private final KeycloakService keycloakService;

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
    public ResponseEntity<String> register(
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
        return ResponseEntity.ok(userId);
    }

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
    @PostMapping("/validate")
    public ResponseEntity<String> validate(
        @Parameter(description = "HTTP request containing the Authorization header")
        HttpServletRequest request
    ) {
        String authHeader = request.getHeader("Authorization");
        String token = authHeader.substring(7); // Remove "Bearer " prefix
        return ResponseEntity.ok(token);
    }

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
    @GetMapping("/user")
    public ResponseEntity<String> fetchUser() {
        String userId = keycloakService.getUserId();
        return ResponseEntity.ok(userId);
    }
} 