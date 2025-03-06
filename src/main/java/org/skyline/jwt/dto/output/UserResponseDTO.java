package org.skyline.jwt.dto.output;

import lombok.*;

import java.util.UUID;

@Builder
@Getter @Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {

    private UUID id;
    private String email;
}
