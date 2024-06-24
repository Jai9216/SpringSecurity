package com.security.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.security.jwt.JwtUtils;
import com.security.jwt.LoginRequest;
import com.security.jwt.LoginResponse;

@RestController
public class GreetingController {
 
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	JwtUtils jwtUtils;

	@GetMapping("/hello")
	public String hello() {
		return "hello";
	}
	
//	PreAuthorize authorize the user based on role before doing the execution of method it Enables by
	// adding a @EnableMethodSecurity annotation at configuration file
	// it gives 403 forbidden exception because are authenticate but you r not authorize
	@PreAuthorize("hasRole('USER')")
	@GetMapping("/user")
	public String userEndPoint() {
		return "hello! User";
	}
	
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/admin")
	public String adminEndpoint() {
		return "hello! admin";
	}
	
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
		Authentication authentication;
		try {
			authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		}catch (AuthenticationException e) {
			Map<String,Object> map = new HashMap<>();
			map.put("message", "Bad credentials");
			map.put("status", false);
			return new ResponseEntity<Object>(map,HttpStatus.NOT_FOUND);
		}
		SecurityContextHolder.getContext().setAuthentication(authentication);
		UserDetails userDetails = (UserDetails)authentication.getPrincipal();
		String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
		
		List<String> roles = userDetails.getAuthorities().stream().map(item-> item.getAuthority()).collect(Collectors.toList());
		
		LoginResponse loginResponse = LoginResponse.builder().jwtToken(jwtToken).username(userDetails.getUsername()).roles(roles).build();
		return ResponseEntity.ok(loginResponse);
	}
	
	
	
}
