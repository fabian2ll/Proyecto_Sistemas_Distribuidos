package uptc.edu.co.ms_auth.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import uptc.edu.co.ms_auth.auth.model.Permission;

import java.util.Optional;

public interface PermissionRepository extends JpaRepository<Permission, Long> {

    Optional<Permission> findByCode(String code);
}
