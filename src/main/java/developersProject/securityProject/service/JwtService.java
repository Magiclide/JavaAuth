package developersProject.securityProject.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import developersProject.securityProject.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private static final String SECRET_KEY = "HFuPo4Cw9Zx4IAZb3I9eIVSyeBZ5pBae6qa6f5XurCLY5WdrpsiLhbPLtRZxtzko";
	
	public String generateJwtTokenWithoutExtraClaims(User userDetails) {
		return generateJwtAcessTokenWithExtraClaims(new HashMap<>(),userDetails);
	}
	
	public boolean isTokenValid(String jwtToken, UserDetails userDetails) {
		final String username=extractUsername(jwtToken);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken));
	}
	
	private boolean isTokenExpired(String jwtToken) {
		return extractExpiration(jwtToken).before(new Date());
	}

	private Date extractExpiration(String jwtToken) {
		return extractClaim(jwtToken,Claims::getExpiration);
	}

	public String generateJwtAcessTokenWithExtraClaims(Map<String,Object> extraClaims, User userDetails) {
		return Jwts.builder()
				.setClaims(extraClaims)
				.setSubject(userDetails.getEmail())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+1000*6*24))
				.signWith(getSignInKey(),SignatureAlgorithm.HS256)
				.compact();
	}
	
	public String generateJwtRefreshTokenWithExtraClaims(Map<String,Object> extraClaims, User userDetails) {
		return Jwts.builder()
				.setClaims(extraClaims)
				.setSubject(userDetails.getEmail())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+1000000*6*24))
				.signWith(getSignInKey(),SignatureAlgorithm.HS256)
				.compact();
	}
	
	
	
	
	public String extractUsername(String jwtToken) {
		return extractClaim(jwtToken,Claims::getSubject);
	}
	
	public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver){
		final Claims claims = extractAllClaims(jwtToken);
		return claimsResolver.apply(claims);
	}
	
	
	private Claims extractAllClaims(String jwtToken) {
		return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(jwtToken).getBody();
	}

	private Key getSignInKey() {
		
		byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
