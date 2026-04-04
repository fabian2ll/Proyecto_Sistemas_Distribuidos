package uptc.edu.co.ms_auth.auth.config;

import co.edu.uptc.shared.security.RoleScopeCatalog;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import uptc.edu.co.ms_auth.auth.model.Permission;
import uptc.edu.co.ms_auth.auth.model.Role;
import uptc.edu.co.ms_auth.auth.repository.PermissionRepository;
import uptc.edu.co.ms_auth.auth.repository.RoleRepository;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@Configuration
public class RbacDataSeeder {

    @Bean
    CommandLineRunner seedRbac(PermissionRepository permissionRepository, RoleRepository roleRepository) {
        return args -> {
            Map<String, Permission> permissions = new LinkedHashMap<>();
            for (String scope : RoleScopeCatalog.allScopes()) {
                Permission permission = permissionRepository.findByCode(scope)
                        .orElseGet(() -> permissionRepository.save(new Permission(scope)));
                permissions.put(scope, permission);
            }

            seedRole(roleRepository, permissions, RoleScopeCatalog.ROLE_ADMIN, RoleScopeCatalog.scopesForRole(RoleScopeCatalog.ROLE_ADMIN));
            seedRole(roleRepository, permissions, RoleScopeCatalog.ROLE_OFFICER, RoleScopeCatalog.scopesForRole(RoleScopeCatalog.ROLE_OFFICER));
            seedRole(roleRepository, permissions, RoleScopeCatalog.ROLE_AUDITOR, RoleScopeCatalog.scopesForRole(RoleScopeCatalog.ROLE_AUDITOR));
        };
    }

    private void seedRole(RoleRepository roleRepository,
                          Map<String, Permission> permissions,
                          String roleName,
                          Set<String> scopeCodes) {
        Role role = roleRepository.findByName(roleName)
                .orElseGet(() -> roleRepository.save(new Role(roleName)));

        Set<Permission> assignedPermissions = new HashSet<>();
        for (String scopeCode : scopeCodes) {
            Permission permission = permissions.get(scopeCode);
            if (permission != null) {
                assignedPermissions.add(permission);
            }
        }

        role.setPermissions(assignedPermissions);
        roleRepository.save(role);
    }
}
