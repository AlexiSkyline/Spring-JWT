package org.skyline.jwt.services;

import lombok.RequiredArgsConstructor;
import org.skyline.jwt.models.RefreshToken;
import org.skyline.jwt.models.User;
import org.skyline.jwt.repositories.RefreshTokenRepository;
import org.skyline.jwt.repositories.UserRepository;
import org.skyline.jwt.services.interfaces.IRefreshTokenService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService implements IRefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Override
    public Optional<RefreshToken> createRefreshToken(String email) {
        Optional<User> userFound = userRepository.findByEmail(email);

        if (userFound.isEmpty()) return Optional.empty();

        RefreshToken refreshToken = RefreshToken.builder()
                .user(userFound.get())
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(600000))
                .build();

        refreshTokenRepository.findByUserId(userFound.get().getId()).ifPresent(refreshTokenRepository::delete);

        return Optional.of(refreshTokenRepository.save(refreshToken));
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    public Boolean verifyExpiration(RefreshToken token) {
        if(token.getExpiryDate().compareTo(Instant.now()) < 0){
            refreshTokenRepository.delete(token);
            return false;
        }

        return true;
    }
}
