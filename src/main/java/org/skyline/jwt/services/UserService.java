package org.skyline.jwt.services;

import lombok.RequiredArgsConstructor;
import org.skyline.jwt.dto.input.UserRequest;
import org.skyline.jwt.dto.output.UserResponse;
import org.skyline.jwt.mappers.UserMapper;
import org.skyline.jwt.models.User;
import org.skyline.jwt.repositories.UserRepository;
import org.skyline.jwt.services.interfaces.IUserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    @Override
    public Optional<UserResponse> saveUser(UserRequest userRequest) {
        Optional<User> userFound =  userRepository.findByEmail(userRequest.getEmail());

        if (userFound.isPresent()) return Optional.empty();

        userRequest.setPassword(this.passwordEncoder.encode(userRequest.getPassword()));
        return Optional.of(userMapper.userToUserResponse(this.userRepository.save(this.userMapper.userRequestToUser(userRequest))));
    }

    @Override
    public Optional<UserResponse> getUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetail = (UserDetails) authentication.getPrincipal();
        String emailFromJwt = userDetail.getUsername();

        return userRepository.findByEmail(emailFromJwt).map(userMapper::userToUserResponse);
    }

    @Override
    public List<UserResponse> getAllUser() {
        return userRepository.findAll().stream().map(userMapper::userToUserResponse).toList();
    }
}
