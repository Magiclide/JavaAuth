package developersProject.securityProject.auth.aspects;

import java.util.HashMap;
import java.util.Map;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import developersProject.securityProject.auth.AuthenticationRequest;
import developersProject.securityProject.auth.service.AuthenticationService;
import developersProject.securityProject.entity.User;
import developersProject.securityProject.repository.UserRepository;
import developersProject.securityProject.service.JwtService;

@Aspect
@Component
public class AuthenticationAspect {

	
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private JwtService jwtService;
	
	@Autowired
	private AuthenticationService authenticationService;
	
	@AfterReturning(pointcut="execution(* developersProject.securityProject.service.JwtService.generateJwtTokenWithoutExtraClaims(..))", returning="result")
	public void generateRefreshToken(JoinPoint joinPoint, Object result) {
		Object[] requestFromThePointCutMethod = joinPoint.getArgs();
		User userDetailsFromPointCutMethodRequest = (User) requestFromThePointCutMethod[0];
		User user = userRepository.findByEmail(userDetailsFromPointCutMethodRequest.getEmail()).get();
		
		
		Map<String,Object> extraClaims = new HashMap<String,Object>();
		extraClaims.put("token_type", "refresh");
		String refreshToken= jwtService.generateJwtRefreshTokenWithExtraClaims(extraClaims,user);
		user.setRefreshToken(refreshToken);
		userRepository.save(user);
		
	}
	/*
	@Before("execution(* developersProject.securityProject.service.AuthenticationService.register(..)")
	public void sendEmailToAuthenticate() {
		
	}
	
	@AfterReturning(pointcut="execution(* developersProject.securityProject.service.AuthenticationService.emailAuthentication())",returning="result")
	public void checkEmailValidationCode(Object result) {
		
	}
	*/
}
