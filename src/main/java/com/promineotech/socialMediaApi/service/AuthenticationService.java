package com.promineotech.socialMediaApi.service;

import java.security.Key;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.promineotech.socialMediaApi.entity.Credentials;
import com.promineotech.socialMediaApi.entity.User;
import com.promineotech.socialMediaApi.repository.UserRepository;
import com.promineotech.socialMediaApi.views.LoggedInView;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class AuthenticationService {

	@Autowired
	private UserRepository userRepository;
	
	private static Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

	public User register(Credentials cred, String role) {
		User user = new User();
		user.setRole(role);
		user.setUsername(cred.getUsername());
		user.setPassword(BCrypt.hashpw(cred.getPassword(), BCrypt.gensalt()));
		return userRepository.save(user);
	}

	public LoggedInView login(Credentials cred) throws Exception {
		User foundUser = userRepository.findByUsername(cred.getUsername());
		if (foundUser != null && BCrypt.checkpw(cred.getPassword(), foundUser.getPassword())) {
			LoggedInView view = new LoggedInView();
			view.setUser(foundUser);
			view.setJwt(generateToken(foundUser));
			return view;
		} else {
			throw new Exception("Invalid username or password.");
		}
	}
	
	public boolean isAdmin(String token) {
		return ((String)Jwts.parser()
				.setSigningKey(key)
				.parseClaimsJws(token)
				.getBody()
				.get("role"))
				.equals("ADMIN");
	}
	
	public boolean isCorrectUser(String jwt, Long userId) {
		return new Long((Integer)Jwts.parser()
				.setSigningKey(key)
				.parseClaimsJws(jwt)
				.getBody()
				.get("userId"))
				.equals(userId);
	}
	
	public String getToken(HttpServletRequest request) throws Exception {
		String header = request.getHeader("Authorization");
		if (header == null) {
			throw new Exception("Request contains no token.");
		}
		return header.replaceAll("Bearer ", "");
	}

	private String generateToken(User user) {
		String jwt = Jwts.builder()
				.claim("role", user.getRole())
				.claim("userId", user.getId())
				.setSubject("PROMINEO TECH JWT")
				.signWith(key)
				.compact();
		return jwt;
	}
}
