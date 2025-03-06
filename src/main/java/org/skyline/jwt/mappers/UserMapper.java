package org.skyline.jwt.mappers;

import org.mapstruct.Mapper;
import org.skyline.jwt.dto.input.UserRequestDTO;
import org.skyline.jwt.dto.output.UserResponseDTO;
import org.skyline.jwt.models.User;

@Mapper
public interface UserMapper {

    User userRequestToUser(UserRequestDTO userRequestDTO);
    UserResponseDTO userToUserResponse(User user);
}
