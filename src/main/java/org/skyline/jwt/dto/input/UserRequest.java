package org.skyline.jwt.dto.input;

import lombok.*;
import org.skyline.jwt.models.Role;

import java.util.HashSet;
import java.util.Set;

@Builder
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserRequest {

    private String email;
    private String password;
    @Builder.Default
    private Set<Role> roles = new HashSet<>();
}
