package org.skyline.jwt.services.interfaces;

import org.skyline.jwt.dto.input.UserRequest;
import org.skyline.jwt.dto.output.UserResponse;

import java.util.List;
import java.util.Optional;

public interface IUserService {

    Optional<UserResponse> saveUser(UserRequest userRequest);
    Optional<UserResponse> getUser();
    List<UserResponse> getAllUser();
}
