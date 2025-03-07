package org.skyline.jwt.services.interfaces;

import jakarta.servlet.http.HttpServletRequest;
import org.skyline.jwt.dto.input.UserRequestDTO;
import org.skyline.jwt.dto.output.UserResponseDTO;

import java.util.List;
import java.util.Optional;

public interface IUserService {

    Optional<UserResponseDTO> saveUser(UserRequestDTO userRequestDTO);
    Optional<UserResponseDTO> getUser();
    List<UserResponseDTO> getAllUser();
    void logout(HttpServletRequest request);
}
