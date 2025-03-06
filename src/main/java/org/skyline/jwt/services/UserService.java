package org.skyline.jwt.services;

import lombok.RequiredArgsConstructor;
import org.skyline.jwt.dto.input.UserRequest;
import org.skyline.jwt.dto.output.UserResponse;
import org.skyline.jwt.enums.TypeRole;
import org.skyline.jwt.helpers.CustomUserDetails;
import org.skyline.jwt.mappers.UserMapper;
import org.skyline.jwt.models.Role;
import org.skyline.jwt.models.User;
import org.skyline.jwt.repositories.RoleRepository;
import org.skyline.jwt.repositories.UserRepository;
import org.skyline.jwt.services.interfaces.IUserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    @Override
    public Optional<UserResponse> saveUser(UserRequest userRequest) {
        Optional<User> userFound =  userRepository.findByEmail(userRequest.getEmail());
        Optional<Role> userRole = roleRepository.findByName(TypeRole.ROLE_USER);

        if (userFound.isPresent() || userRole.isEmpty()) return Optional.empty();

        userRequest.setPassword(this.passwordEncoder.encode(userRequest.getPassword()));
        User newUser = this.userMapper.userRequestToUser(userRequest);
        newUser.setRoles(Collections.singleton(userRole.get()));

        return Optional.of(userMapper.userToUserResponse(this.userRepository.save(newUser)));
    }

    @Override
    public Optional<UserResponse> getUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails userDetail = (CustomUserDetails) authentication.getPrincipal();
        String emailFromJwt = userDetail.getEmail();

        return userRepository.findByEmail(emailFromJwt).map(userMapper::userToUserResponse);
    }

    @Override
    public List<UserResponse> getAllUser() {
        return userRepository.findAll().stream().map(userMapper::userToUserResponse).toList();
    }
}
