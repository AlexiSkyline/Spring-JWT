package org.skyline.jwt.dto.input;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import io.swagger.v3.oas.annotations.media.Schema;

@Builder
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserRequestDTO {

    @Email
    @NonNull
    @NotBlank
    @Schema(description = "The email of the user to be registered. Must be a valid email format.", example = "newuser@example.com")
    private String email;

    @NonNull
    @NotBlank
    @Schema(description = "The password for the user being registered. Must not be blank.", example = "password123")
    private String password;
}
