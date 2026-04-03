package uptc.edu.co.ms_auth.auth.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import uptc.edu.co.ms_auth.auth.model.Permission;
import uptc.edu.co.ms_auth.auth.model.Role;
import uptc.edu.co.ms_auth.auth.repository.PermissionRepository;
import uptc.edu.co.ms_auth.auth.repository.RoleRepository;

import java.util.HashSet;
import java.util.Set;

@Configuration
public class RbacDataSeeder {

    @Bean
    CommandLineRunner seedRbac(PermissionRepository permissionRepository, RoleRepository roleRepository) {
        return args -> {
            Permission createContract = permissionRepository.findByCode("create:contract")
                    .orElseGet(() -> permissionRepository.save(new Permission("create:contract")));
            Permission viewAudit = permissionRepository.findByCode("view:audit")
                    .orElseGet(() -> permissionRepository.save(new Permission("view:audit")));

            Role user = roleRepository.findByName("USER")
                    .orElseGet(() -> roleRepository.save(new Role("USER")));
            Role admin = roleRepository.findByName("ADMIN")
                    .orElseGet(() -> roleRepository.save(new Role("ADMIN")));

            if (user.getPermissions().isEmpty()) {
                user.setPermissions(new HashSet<>(Set.of(viewAudit)));
                roleRepository.save(user);
            }

            if (admin.getPermissions().isEmpty()) {
                admin.setPermissions(new HashSet<>(Set.of(createContract, viewAudit)));
                roleRepository.save(admin);
            }
        };
    }
}
