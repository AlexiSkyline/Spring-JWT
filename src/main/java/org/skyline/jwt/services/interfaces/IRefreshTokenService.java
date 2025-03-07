package org.skyline.jwt.services.interfaces;

import org.skyline.jwt.models.RefreshToken;

import java.util.Optional;

public interface IRefreshTokenService {

    Optional<RefreshToken> createRefreshToken(String email);
    Optional<RefreshToken> findByToken(String token);
    void deleteByUserEmail(String email);
    Boolean verifyExpiration(RefreshToken token);
}
