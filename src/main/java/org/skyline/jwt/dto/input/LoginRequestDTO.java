package org.skyline.jwt.dto.input;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Builder
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequestDTO {

    @Email
    @NonNull
    @NotBlank
    private String email;

    @NonNull
    @NotBlank
    private String password;
}

