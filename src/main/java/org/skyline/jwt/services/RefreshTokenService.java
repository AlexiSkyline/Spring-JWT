package org.skyline.jwt.services;

import lombok.RequiredArgsConstructor;
import org.skyline.jwt.models.RefreshToken;
import org.skyline.jwt.models.User;
import org.skyline.jwt.repositories.RefreshTokenRepository;
import org.skyline.jwt.repositories.UserRepository;
import org.skyline.jwt.security.JwtUtils;
import org.skyline.jwt.services.interfaces.IRefreshTokenService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService implements IRefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    @Override
    @Transactional
    public Optional<RefreshToken> createRefreshToken(String email) {
        Optional<User> userFound = userRepository.findByEmail(email);

        if (userFound.isEmpty()) return Optional.empty();

        RefreshToken refreshToken = refreshTokenRepository.findByUserId(userFound.get().getId())
                .map(existingToken -> jwtUtils.refreshOrCreateToken(existingToken, userFound.get()))
                .orElse(jwtUtils.createRefreshToken(userFound.get()));

        return Optional.of(refreshTokenRepository.save(refreshToken));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    @Transactional
    public Boolean verifyExpiration(RefreshToken token) {
        if(token.getExpiryDate().compareTo(Instant.now()) < 0){
            refreshTokenRepository.delete(token);
            return false;
        }

        return true;
    }

    @Override
    @Transactional
    public void deleteByUserEmail(String email) {
        refreshTokenRepository.findByUserEmail(email)
                .ifPresent((refreshTokenRepository::delete));
    }
}
