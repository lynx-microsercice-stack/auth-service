package lynx.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.Components;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Auth Service API")
                        .description("""
                            Authentication and Authorization Service using Keycloak.
                            
                            This service provides endpoints for:
                            - User registration and management
                            - Authentication and token management
                            - Role-based access control
                            - Session management
                            
                            All endpoints except /auth/register and /auth/login require a valid JWT token.
                            """)
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Lynx Team")
                                .email("support@lynx.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("http://www.apache.org/licenses/LICENSE-2.0.html")))
                .servers(List.of(
                        new Server().url("").description("Current Server"),
                        new Server().url("http://localhost:8081").description("Local Development Server"),
                        new Server().url("https://auth.lynx.com").description("Production Server")
                ))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT token obtained from the /auth/login endpoint")));
    }
} 