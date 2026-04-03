package uptc.edu.co.ms_auth.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import uptc.edu.co.ms_auth.auth.model.Role;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String name);

    List<Role> findByNameIn(Set<String> names);
}
