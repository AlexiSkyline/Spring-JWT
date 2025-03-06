package org.skyline.jwt.controllers;

import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.skyline.jwt.dto.input.AuthRequestDTO;
import org.skyline.jwt.dto.input.RefreshTokenRequestDTO;
import org.skyline.jwt.dto.input.UserRequest;
import org.skyline.jwt.dto.output.JwtResponseDTO;
import org.skyline.jwt.dto.output.UserResponse;
import org.skyline.jwt.models.RefreshToken;
import org.skyline.jwt.security.JwtUtils;
import org.skyline.jwt.services.interfaces.IRefreshTokenService;
import org.skyline.jwt.services.interfaces.IUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class UserController {

    private final IUserService userService;
    private final JwtUtils jwtUtils;
    private final IRefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;

    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUser());
    }

    @GetMapping("/profile")
    public ResponseEntity<UserResponse> getUserProfile() throws BadRequestException {
        UserResponse userResponse = userService.getUser().orElseThrow(() -> new BadRequestException("User not exists"));
        return ResponseEntity.ok(userResponse);
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    public String test() {
        return "Welcome";
    }

    @PostMapping("/register")
    public ResponseEntity<JwtResponseDTO> register(@RequestBody UserRequest userRequest) throws BadRequestException {
        UserResponse userResponse = userService.saveUser(userRequest).orElseThrow(() -> new BadRequestException("User already exists"));

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userResponse.getEmail())
                .orElseThrow(() -> new RuntimeException("Failed to create refresh token"));

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(buildJwtResponse(userResponse.getEmail(), refreshToken.getToken()));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponseDTO> authenticateAndGetToken(@RequestBody AuthRequestDTO authRequestDTO) throws BadRequestException {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequestDTO.getEmail(), authRequestDTO.getPassword())
        );

        if (!authentication.isAuthenticated()) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequestDTO.getEmail())
                .orElseThrow(() -> new RuntimeException("Failed to create refresh token"));

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(buildJwtResponse(authRequestDTO.getEmail(), refreshToken.getToken()));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JwtResponseDTO> refreshToken(@RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO) {
        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenRequestDTO.getToken())
                .filter(refreshTokenService::verifyExpiration)
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found or expired"));

        return ResponseEntity.ok(buildJwtResponse(refreshToken.getUser().getEmail(), refreshToken.getToken()));
    }

    private JwtResponseDTO buildJwtResponse(String email, String refreshToken) {
        return JwtResponseDTO.builder()
                .accessToken(jwtUtils.generateToken(email))
                .token(refreshToken)
                .build();
    }
}
