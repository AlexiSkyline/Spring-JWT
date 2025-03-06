package org.skyline.jwt.repositories;

import org.skyline.jwt.models.User;
import org.springframework.data.repository.CrudRepository;

import java.util.UUID;

public interface UserRepository extends CrudRepository<User, UUID> {

    User findByEmail(String email);
    User findFirstById(UUID id);
}
