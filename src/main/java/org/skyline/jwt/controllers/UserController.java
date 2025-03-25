package org.skyline.jwt.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.skyline.jwt.dto.input.LoginRequestDTO;
import org.skyline.jwt.dto.input.RefreshTokenRequestDTO;
import org.skyline.jwt.dto.input.UserRequestDTO;
import org.skyline.jwt.dto.output.ErrorResponse;
import org.skyline.jwt.dto.output.JwtResponseDTO;
import org.skyline.jwt.dto.output.UserResponseDTO;
import org.skyline.jwt.models.RefreshToken;
import org.skyline.jwt.models.exception.EmailAlreadyExistsException;
import org.skyline.jwt.models.exception.InvalidCredentialsException;
import org.skyline.jwt.models.exception.RefreshTokenNotFoundException;
import org.skyline.jwt.models.exception.UserNotFoundException;
import org.skyline.jwt.security.JwtUtils;
import org.skyline.jwt.services.interfaces.IRefreshTokenService;
import org.skyline.jwt.services.interfaces.IUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Endpoints related to authentication, including login, logout, and token management.")
public class UserController {

    private final IUserService userService;
    private final JwtUtils jwtUtils;
    private final IRefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;

    @GetMapping("/users")
    @SecurityRequirement(name = "BearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
            summary = "Retrieve all registered users",
            description = """
                Retrieves a paginated list of all registered users in the system.
                Requires ADMIN privileges.
                The response includes complete user details including roles and status.
                \n\n**Access Control:**\n- Role: ADMIN
                \n**Note:** Sensitive information like passwords is never included in the response.
            """,
            tags = { "Authentication" },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successfully retrieved list of users",
                            content = @Content(
                                    mediaType = "application/json",
                                    array = @ArraySchema(schema = @Schema(implementation = UserResponseDTO.class))
                            )
                    )
            }
    )
    public ResponseEntity<List<UserResponseDTO>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUser());
    }

    @GetMapping("/profile")
    @SecurityRequirement(name = "BearerAuth")
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    @Operation(
            summary = "Retrieve all registered users",
            description = """
               Retrieves the complete profile information of the currently authenticated user.
              \s
               **Access Requirements:**
               - Authenticated user (ADMIN or USER role)
              \s
               **Response Includes:**
               - User ID
               - Email
              \s
               **Security Notes:**
               - Requires valid JWT token in Authorization header
               - Users can only access their own profile through this endpoint
               - Sensitive fields like password are never exposed
            """,
            tags = { "Authentication" },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successfully retrieved user profile",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(
                                            implementation = UserResponseDTO.class,
                                            description = "Complete user profile information"
                                    )
                            )
                    )
            }
    )
    public ResponseEntity<UserResponseDTO> getUserProfile() {
        UserResponseDTO userResponseDTO = userService.getUser()
                .orElseThrow(() -> new UserNotFoundException("User not exists"));
        return ResponseEntity.ok(userResponseDTO);
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "BearerAuth")
    @Operation(
            summary = "Admin access test endpoint",
            description = """
            Simple endpoint to verify ADMIN role access and API functionality.
            
            **Purpose:**
            - Verify JWT authentication
            - Test ADMIN role authorization
            - Check basic API connectivity
            
            **Access Requirements:**
            - Valid JWT token with ADMIN role in Authorization header
            """,
            tags = { "Authentication" },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successfully verified ADMIN access",
                            content = @Content(
                                    mediaType = "text/plain",
                                    schema = @Schema(
                                            type = "string",
                                            example = "Welcome",
                                            description = "Simple success message confirming access"
                                    )
                            )
                    ),
            }
    )
    public String test() {
        return "Welcome";
    }

    @PostMapping("/register")
    @Operation(
            summary = "Register a new user account",
            description = """
            Creates a new user account in the system and returns authentication tokens.
            
            **Validation Rules:**
            - Email must be valid and unique
            - Password must meet complexity requirements
            - Required fields must not be empty
            
            **Response Includes:**
            - JWT access token
            - Refresh token
            
            **Security Notes:**
            - No authentication required
            - Sensitive data is never returned in the response
            """,
            tags = { "Authentication" },
            responses = {
                    @ApiResponse(
                            responseCode = "201",
                            description = "User successfully registered",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(
                                            implementation = JwtResponseDTO.class
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Bad Request - Invalid input data",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(
                                            implementation =ErrorResponse.class,
                                            example = """
                                            {
                                              "timestamp": "2023-08-15T12:34:56.789Z",
                                              "status": 400,
                                              "error": "Bad Request",
                                              "message": [
                                                {
                                                  "message": "must be a valid email address",
                                                  "param": "email",
                                                  "location": "body"
                                                },
                                                {
                                                  "message": "size must be between 8 and 32",
                                                  "param": "password",
                                                  "location": "body"
                                                }
                                              ],
                                              "path": "/api/register"
                                            }"""
                                    )
                            )
                    ),
            }
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User registration details",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = UserRequestDTO.class)
            )
    )
    public ResponseEntity<JwtResponseDTO> register(@Valid @RequestBody UserRequestDTO userRequestDTO) {
        UserResponseDTO userResponseDTO = userService.saveUser(userRequestDTO)
                .orElseThrow(() -> new EmailAlreadyExistsException("Email is already in use"));

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userResponseDTO.getEmail())
                .orElseThrow(() -> new RuntimeException("Failed to create refresh token"));

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(buildJwtResponse(userResponseDTO.getEmail(), refreshToken.getToken()));
    }

    @PostMapping("/login")
    @Operation(
            summary = "Authenticate user and generate tokens",
            description = """
            Authenticates user credentials and returns JWT tokens for authorization.
            
            **Authentication Flow:**
            1. Validates email and password
            2. Verifies user credentials against database
            3. Generates new JWT access token
            4. Creates refresh token for future token renewal
            
            **Security Notes:**
            - Requires valid user credentials
            - Passwords are encrypted/hashed (never stored in plain text)
            - Refresh tokens should be stored securely (HttpOnly cookies recommended)
            
            **Token Information:**
            - Access token typically expires in 15-60 minutes
            - Refresh token typically expires in 7-30 days
            """,
            tags = { "Authentication" },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Authentication successful",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(
                                            implementation = JwtResponseDTO.class
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Bad Request - Invalid input format",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(
                                            implementation = ErrorResponse.class,
                                            example = """
                                            {
                                                "timestamp": "2023-08-15T12:34:56.789Z",
                                                "status": 400,
                                                "error": "Bad Request",
                                                "message": [
                                                    {
                                                        "message": "Email must be valid",
                                                        "field": "email",
                                                        "location": "body"
                                                    },
                                                    {
                                                        "message": "Password must not be empty",
                                                        "field": "password",
                                                        "location": "body"
                                                    }
                                                ],
                                                "path": "/api/login"
                                            }
                                            """
                                    )
                            )
                    ),
            }
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User login credentials",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = LoginRequestDTO.class)
            )
    )
    public ResponseEntity<JwtResponseDTO> login(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDTO.getEmail(), loginRequestDTO.getPassword())
        );

        if (!authentication.isAuthenticated()) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(loginRequestDTO.getEmail())
                .orElseThrow(() -> new RuntimeException("Failed to create refresh token"));

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(buildJwtResponse(loginRequestDTO.getEmail(), refreshToken.getToken()));
    }

    @PostMapping("/refresh-token")
    @SecurityRequirement(name = "BearerAuth")
    @Operation(
            summary = "Refresh authentication tokens",
            description = """
            Generates new access token using a valid refresh token.
            
            **Flow:**
            1. Validates the refresh token
            2. Verifies it's not expired
            3. Issues new JWT access token
            
            **Security Requirements:**
            - Valid refresh token in request body
            - Original JWT in Authorization header (optional, depends on implementation)
            
            **Token Lifetime:**
            - Refresh token typically has longer expiration than access token
            - Both tokens become invalid after this operation if implementing token rotation
            """,
            tags = { "Authentication" },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "New tokens generated successfully",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(
                                            implementation = JwtResponseDTO.class
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Bad Request - Invalid refresh token format",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(
                                            implementation = ErrorResponse.class,
                                            example = """
                                            {
                                              "timestamp": "2023-08-15T12:34:56.789Z",
                                              "status": 400,
                                              "error": "Bad Request",
                                              "message": [
                                                {
                                                  "message": "Refresh token is required",
                                                  "param": "token",
                                                  "location": "body"
                                                }
                                              ],
                                              "path": "/api/register"
                                            }
                                            """
                                    )
                            )
                    ),
            }
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Refresh token details",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = RefreshTokenRequestDTO.class)
            )
    )
    public ResponseEntity<JwtResponseDTO> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO) {
        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenRequestDTO.getRefreshToken())
                .filter(refreshTokenService::verifyExpiration)
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found or expired"));

        return ResponseEntity.ok(buildJwtResponse(refreshToken.getUser().getEmail(), refreshToken.getToken()));
    }

    @PostMapping("/logout")
    @SecurityRequirement(name = "BearerAuth")
    @Operation(
            summary = "Logout user and invalidate tokens",
            description = """
            Invalidates the current user's authentication tokens and performs logout.
            
            **Security Flow:**
            1. Validates JWT from Authorization header
            2. Deletes all refresh tokens for the user
            3. Invalidates the current access token
            
            **Requirements:**
            - Valid JWT token in Authorization header
            - User must be authenticated
            
            **Side Effects:**
            - All refresh tokens for this user will be revoked
            - Subsequent requests with the same access token will fail
            """,
            tags = { "Authentication" }
    )
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);
        String email = jwtUtils.extractUsername(token);

        refreshTokenService.deleteByUserEmail(email);
        userService.logout(request);
        return ResponseEntity.noContent().build();
    }

    private JwtResponseDTO buildJwtResponse(String email, String refreshToken) {
        return JwtResponseDTO.builder()
                .accessToken(jwtUtils.generateToken(email))
                .refreshToken(refreshToken)
                .build();
    }
}
