package org.skyline.jwt.dto.input;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import io.swagger.v3.oas.annotations.media.Schema;

@Builder
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequestDTO {

    @Email
    @NonNull
    @NotBlank
    @Schema(description = "The email of the user attempting to log in. Must be a valid email format.", example = "user@example.com")
    private String email;

    @NonNull
    @NotBlank
    @Schema(description = "The password of the user attempting to log in. Must not be blank.", example = "password123")
    private String password;
}
