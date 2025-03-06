package org.skyline.jwt.bootstrap;

import lombok.RequiredArgsConstructor;
import org.skyline.jwt.enums.TypeRole;
import org.skyline.jwt.models.Role;
import org.skyline.jwt.repositories.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class BootstrapData implements CommandLineRunner {

    private final RoleRepository roleRepository;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        loadRoleData();
    }

    private void loadRoleData() {

        if (roleRepository.count() == 0) {
            var admin = Role.builder()
                    .name(TypeRole.ROLE_ADMIN)
                    .build();

            var userRole = Role.builder()
                    .name(TypeRole.ROLE_USER)
                    .build();
            roleRepository.saveAll(Arrays.asList(admin, userRole));
        }
    }
}
