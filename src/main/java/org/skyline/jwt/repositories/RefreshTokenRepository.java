package org.skyline.jwt.repositories;

import org.skyline.jwt.models.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByUserId(UUID id);
    Optional<RefreshToken> findByUserEmail(String email);
}
