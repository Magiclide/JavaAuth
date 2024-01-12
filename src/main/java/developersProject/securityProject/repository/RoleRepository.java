package developersProject.securityProject.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import developersProject.securityProject.entity.Role;

public interface RoleRepository  extends JpaRepository<Role,Long>{

	Role findByName(String string);

}
