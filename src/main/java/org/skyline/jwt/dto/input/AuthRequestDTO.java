package org.skyline.jwt.dto.input;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequestDTO {

    private String username;
    private String password;
}

