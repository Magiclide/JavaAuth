package developersProject.securityProject.entity;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name="_user")
public class User {

	@jakarta.persistence.Id
	@GeneratedValue
	private Long Id;
	
	private String firstName;
	
	private String lastName;
	
	private String email;
	
	private String password;
	
	private String refreshToken;
	
	private boolean isEnabled;
	
	  @ManyToMany(fetch = FetchType.EAGER) 
	    @JoinTable( 
	        name = "users_roles", 
	        joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"),
	        inverseJoinColumns = @JoinColumn(name = "privilege_id", referencedColumnName="id" ))
	    private Collection<Role> roles;
	

	
	

	
}
