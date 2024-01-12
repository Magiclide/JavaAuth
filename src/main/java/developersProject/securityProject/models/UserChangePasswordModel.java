package developersProject.securityProject.models;

import jakarta.annotation.Nonnull;
import lombok.Data;

@Data
public class UserChangePasswordModel{
	@Nonnull
	private String email;
	@Nonnull
	private String oldPassword;
	@Nonnull
	private String newPassword;
	
	
}

