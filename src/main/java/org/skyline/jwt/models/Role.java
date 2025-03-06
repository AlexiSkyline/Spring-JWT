package org.skyline.jwt.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UuidGenerator;
import org.hibernate.type.SqlTypes;
import org.skyline.jwt.enums.TypeRole;

import java.util.UUID;

@Entity
@Builder
@Setter @Getter
@NoArgsConstructor
@AllArgsConstructor
public class Role {

    @Id
    @UuidGenerator
    @JdbcTypeCode(SqlTypes.CHAR)
    @GeneratedValue(generator = "UUID")
    @Column(length = 36, columnDefinition = "varchar(36)", updatable = false, nullable = false)
    private UUID id;

    @Enumerated( EnumType.STRING )
    private TypeRole name;
}
