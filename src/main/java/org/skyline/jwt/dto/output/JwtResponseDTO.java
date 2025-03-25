package org.skyline.jwt.dto.output;


import lombok.*;

@Builder
@Getter @Setter
@AllArgsConstructor
public class JwtResponseDTO {

    private String accessToken;
    private String refreshToken;
}
