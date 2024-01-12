package developersProject.securityProject.auth.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import developersProject.securityProject.auth.AuthenticationRequest;
import developersProject.securityProject.auth.AuthenticationResponse;
import developersProject.securityProject.auth.RegisterRequest;
import developersProject.securityProject.auth.service.AuthenticationService;
import developersProject.securityProject.entity.User;
import developersProject.securityProject.models.TokenInfo;
import developersProject.securityProject.repository.UserRepository;
import developersProject.securityProject.service.JwtService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

	
	@Autowired
	private UserRepository userRepository;
	
	private final AuthenticationService authenticationService;
	
	@PostMapping("/register")
	public void register(@RequestBody RegisterRequest request) throws Exception{	
		authenticationService.emailVerification(request);
	}
	
	@PostMapping("/verify")
	public ResponseEntity<String> verifyEmailCode(@RequestParam String verifCode) throws Exception {
		if(authenticationService.verificationTokens.containsKey(verifCode)) {
			
			TokenInfo tokenInfo = authenticationService.verificationTokens.get(verifCode);
			
			if(!authenticationService.verifyToken(verifCode)) {
				userRepository.deleteById(tokenInfo.getUserId());
				return ResponseEntity
	                    .badRequest()
	                    .body("Token expired");
			}
			
			User user = userRepository.findById(tokenInfo.getUserId()).get();
			user.setEnabled(true);
			userRepository.save(user);
			authenticationService.verificationTokens.remove(verifCode);
			
			return ResponseEntity.ok("Sucessful Verification");
		}else {
			
			  return ResponseEntity
	                    .badRequest()
	                    .body("An error occured in the verification process");
		}
		
		
	}
	
	
	@PostMapping("/authenticate")
	public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
		return ResponseEntity.ok(authenticationService.authenticate(request));
	}
	
}