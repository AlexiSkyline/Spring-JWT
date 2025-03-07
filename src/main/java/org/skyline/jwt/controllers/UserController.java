package org.skyline.jwt.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.skyline.jwt.dto.input.LoginRequestDTO;
import org.skyline.jwt.dto.input.RefreshTokenRequestDTO;
import org.skyline.jwt.dto.input.UserRequestDTO;
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
public class UserController {

    private final IUserService userService;
    private final JwtUtils jwtUtils;
    private final IRefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;

    @GetMapping("/users")
    public ResponseEntity<List<UserResponseDTO>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUser());
    }

    @GetMapping("/profile")
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    public ResponseEntity<UserResponseDTO> getUserProfile() {
        UserResponseDTO userResponseDTO = userService.getUser().orElseThrow(() -> new UserNotFoundException("User not exists"));
        return ResponseEntity.ok(userResponseDTO);
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    public String test() {
        return "Welcome";
    }

    @PostMapping("/register")
    public ResponseEntity<JwtResponseDTO> register(@Valid @RequestBody UserRequestDTO userRequestDTO) {
        UserResponseDTO userResponseDTO = userService.saveUser(userRequestDTO).orElseThrow(() -> new EmailAlreadyExistsException("Email is already in use"));

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userResponseDTO.getEmail())
                .orElseThrow(() -> new RuntimeException("Failed to create refresh token"));

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(buildJwtResponse(userResponseDTO.getEmail(), refreshToken.getToken()));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponseDTO> authenticateAndGetToken(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {
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
    public ResponseEntity<JwtResponseDTO> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO) {
        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenRequestDTO.getToken())
                .filter(refreshTokenService::verifyExpiration)
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found or expired"));

        return ResponseEntity.ok(buildJwtResponse(refreshToken.getUser().getEmail(), refreshToken.getToken()));
    }

    @PostMapping("/logout")
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
                .token(refreshToken)
                .build();
    }
}
