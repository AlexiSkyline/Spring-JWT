package org.skyline.jwt.dto.input;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenRequestDTO {

    @NonNull
    @NotBlank
    @Schema(description = "The refresh token used to request a new access token.", example = "abcdef1234567890")
    private String refreshToken;
}
