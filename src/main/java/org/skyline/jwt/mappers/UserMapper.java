package org.skyline.jwt.mappers;

import org.mapstruct.Mapper;
import org.skyline.jwt.dto.input.UserRequest;
import org.skyline.jwt.dto.output.UserResponse;
import org.skyline.jwt.models.User;

@Mapper
public interface UserMapper {

    User userRequestToUser(UserRequest userRequest);
    UserResponse userToUserResponse(User user);
}
