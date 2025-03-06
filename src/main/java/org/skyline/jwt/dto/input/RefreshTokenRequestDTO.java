package org.skyline.jwt.dto.input;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenRequestDTO {

    @NonNull
    @NotBlank
    private String token;
}

