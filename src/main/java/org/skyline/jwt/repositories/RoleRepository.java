package org.skyline.jwt.repositories;

import org.skyline.jwt.enums.TypeRole;
import org.skyline.jwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findByName(TypeRole name);
}
