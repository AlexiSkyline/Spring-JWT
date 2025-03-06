package org.skyline.jwt.dto.input;

import lombok.*;

@Builder
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserRequest {

    private String email;
    private String password;
}
