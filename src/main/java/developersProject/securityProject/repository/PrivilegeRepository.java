package developersProject.securityProject.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import developersProject.securityProject.entity.Privilege;



public interface PrivilegeRepository extends JpaRepository<Privilege, Long>{

	Privilege findByName(String name);

}
