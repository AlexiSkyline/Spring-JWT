package org.skyline.jwt.dto.output;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponseDTO {

    private String accessToken;
    private String token;
}
