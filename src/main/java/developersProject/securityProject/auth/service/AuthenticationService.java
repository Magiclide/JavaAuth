package developersProject.securityProject.auth.service;


import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import developersProject.securityProject.auth.AuthenticationRequest;
import developersProject.securityProject.auth.AuthenticationResponse;
import developersProject.securityProject.auth.RegisterRequest;

import developersProject.securityProject.entity.Role;
import developersProject.securityProject.entity.User;
import developersProject.securityProject.models.TokenInfo;
import developersProject.securityProject.repository.RoleRepository;
import developersProject.securityProject.repository.UserRepository;
import developersProject.securityProject.service.JwtService;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@EnableAspectJAutoProxy
public class AuthenticationService {
	
	
	private final UserRepository userRepository;
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	private RoleRepository roleRepository;
	
	private final JwtService jwtService;
	
	private final AuthenticationManager authenticationManager;
	
	 public Map<String, TokenInfo> verificationTokens = new HashMap<>();
	
	
	//Aqui nós podemos pensar em não gerar o token e somente registrar o usuario no database para depois ele poder se autenticar.
	public void emailVerification(RegisterRequest request) {
		
		String verifCode = emailAuthentication();
		Role adminRole = roleRepository.findByName("ROLE_ADMIN");
		
		User user = User.builder().firstName(request.getFirstName())
				.lastName(request.getLastName())
				.email(request.getEmail())
				.password(passwordEncoder.encode(request.getPassword()))
				.roles(Arrays.asList(adminRole))
				.isEnabled(false)
				
				.build();
			userRepository.save(user);
		verificationTokens.put(verifCode,new TokenInfo(user.getId(), LocalDateTime.now()));
	}
	public boolean verifyToken(String verifCode) {
        TokenInfo tokenInfo = verificationTokens.get(verifCode);

        if (tokenInfo != null) {
            LocalDateTime creationTime = tokenInfo.getCreationTime();
            LocalDateTime currentTime = LocalDateTime.now();
            Duration duration = Duration.between(creationTime, currentTime);

            // Define the expiration time (e.g., 24 hours)
            long expirationTimeInHours = 1;

            // Check if the token has expired
            if (duration.toMinutes() <= expirationTimeInHours) {
                // Token is valid
                return true;
            } else {
                
                verificationTokens.remove(verifCode);
            }
        }

        // Token is not valid or has expired
        return false;
    }

	
	
	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
				request.getEmail(),
				request.getPassword()));
		
		User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
		String jwtToken = jwtService.generateJwtTokenWithoutExtraClaims(user);
		return AuthenticationResponse.builder().token(jwtToken).build();
	}
	
	
	public String emailAuthentication() {
		String username = "enzo.monteiro@hotmail.com";
        String password = "321654987aA@";

	    String to = "enzofofis@hotmail.com"; 
	    String from = "enzo.monteiro@hotmail.com";  
	    
	  
	       
	      Properties properties = System.getProperties();  
	      	properties.put("mail.smtp.auth", "true");
	      	properties.put("mail.smtp.starttls.enable", "true");
	      	properties.put("mail.smtp.ssl.trust", "smtp-mail.outlook.com");
	      	properties.put("mail.smtp.host", "smtp-mail.outlook.com");
	      	properties.put("mail.smtp.port", "587");
	      
	       
	     
	      Session session = Session.getInstance(properties);
	      String verifCode="";
	      
	      	do {	
	      		 verifCode=UUID.randomUUID().toString();
	      		
	      	}while(verificationTokens.containsKey(verifCode));
	          String verificationLink = "http://localhost:8080/api/v1/auth/verify?verifCode=" + verifCode;
	          
	      
	      try{  
	         MimeMessage message = new MimeMessage(session);  
	         message.setFrom(new InternetAddress(from));  
	         message.addRecipient(Message.RecipientType.TO,new InternetAddress(to));  
	         message.setSubject("VERIFICATION CODE");  
	         message.setText("Hello, your verification link is: "+verificationLink);  
	  
	           
	         Transport.send(message,username,password);  
	         return verifCode.toString();  
	  
	      }catch (MessagingException mex) {mex.printStackTrace();
	      return "Error sending the email";
	      }  
	   }  
	

}
