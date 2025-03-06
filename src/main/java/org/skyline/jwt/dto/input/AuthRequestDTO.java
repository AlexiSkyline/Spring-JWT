package org.skyline.jwt.dto.input;

import lombok.*;

@Builder
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequestDTO {

    private String email;
    private String password;
}

