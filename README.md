# Auth Service

This service handles authentication and authorization using Keycloak. It provides endpoints for user registration, login, and logout.

## Prerequisites

- Java 17 or later
- Docker and Docker Compose
- Gradle

## Setup

1. Clone the repository
2. Start the development environment:
   ```bash
   docker-compose up -d
   ```
3. Wait for Keycloak to start (it may take a few minutes)
4. Access the Keycloak Admin Console at http://localhost:8081
   - Username: admin
   - Password: admin
5. Create a new realm named "lynx"
6. Create a new client named "auth-service"
   - Client Protocol: openid-connect
   - Access Type: confidential
   - Valid Redirect URIs: http://localhost:8080/*
   - Web Origins: http://localhost:8080
7. Get the client secret from the Credentials tab and set it as an environment variable:
   ```bash
   export KEYCLOAK_CLIENT_SECRET=your-client-secret
   ```
8. Create a role named "USER" in the realm
9. Build the project:
   ```bash
   ./gradlew build
   ```
10. Run the application:
    ```bash
    ./gradlew bootRun
    ```

## API Endpoints

### Register
```http
POST /api/auth/register
Content-Type: application/json

{
    "username": "user",
    "password": "password",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
}
```

### Login
```http
POST /api/auth/login
Content-Type: application/json

{
    "username": "user",
    "password": "password"
}
```

### Logout
```http
POST /api/auth/logout
Authorization: Bearer <access_token>
```

## Development

The project uses:
- Spring Boot 3.2.3
- Keycloak 21.1.1
- PostgreSQL 16
- Gradle

## Testing

Run the tests:
```bash
./gradlew test
```

Generate test coverage report:
```bash
./gradlew jacocoTestReport
```

## Code Quality

The project uses:
- Checkstyle for code style
- PMD for static code analysis
- SpotBugs for bug detection
- SonarQube for code quality monitoring

Run code quality checks:
```bash
./gradlew check
``` # auth-service
