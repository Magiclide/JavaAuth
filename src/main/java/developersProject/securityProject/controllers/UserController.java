package developersProject.securityProject.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import developersProject.securityProject.auth.AuthenticationRequest;
import developersProject.securityProject.auth.AuthenticationResponse;
import developersProject.securityProject.auth.service.AuthenticationService;
import developersProject.securityProject.entity.User;
import developersProject.securityProject.models.UserChangePasswordModel;
import developersProject.securityProject.repository.UserRepository;
import developersProject.securityProject.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;

@RestController
public class UserController {

	@Autowired
	private AuthenticationService authenticationService;
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private JwtService jwtService;
	
	@PutMapping("api/changePassword")
	public ResponseEntity<String> changePassword(@RequestBody UserChangePasswordModel userChangePasswordModel,HttpServletRequest request) throws Exception{
		final String authHeader = request.getHeader("Authorization");
		String jwtToken = authHeader.substring(7);
		
		User user = userRepository.findByEmail(userChangePasswordModel.getEmail()).get();
		if(user == null)throw new UsernameNotFoundException("This email does not exist in the database");
		String username = jwtService.extractUsername(jwtToken);
		
		if(!username.equals(userChangePasswordModel.getEmail()))throw new Exception("You cannot change password to other users");
		if(!passwordEncoder.matches(userChangePasswordModel.getOldPassword(), user.getPassword()))throw new Exception("An error occured");
		
		user.setPassword(passwordEncoder.encode(userChangePasswordModel.getNewPassword()));
		userRepository.save(user);
		
		return ResponseEntity.status(HttpStatus.OK).body("Senha alterada com sucesso");
	}
	
}
