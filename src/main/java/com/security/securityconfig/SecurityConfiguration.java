package com.security.securityconfig;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.security.jwt.AuthEntryPointJwt;
import com.security.jwt.AuthTokenFilter;

import lombok.Builder;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {
	
	@Autowired
	DataSource dataSource;
	
	// By default it uses base64 encode to encode username and password as (admin:demo@123) -> YWRtaW46ZGVtb0AxMjM=
    //	Spring Security defaults maintain a session
	// This bean is requires to set custom security configuration otherwise it set default form based authentication
//	@Bean
//	SecurityFilterChain getFilterChain(HttpSecurity http) throws Exception {
//		 //In this endpoint "/h2-console/**" every request is permited
//		http.authorizeHttpRequests((requests)-> requests.requestMatchers("/h2-console/**").permitAll()
//				 //In this every endPoint is authenticated
//				.anyRequest().authenticated());
//		// It is for form based authentication provides default form
//		http.formLogin(Customizer.withDefaults());
//		// Its is for basic authentication for software like postman etc
//		http.httpBasic(Customizer.withDefaults());  
//		// It is used to change session regarding things like policy and all
////		http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//		
////		It Enables the view of h2 database
//		http.headers(headers-> headers.frameOptions(frameOptions-> frameOptions.sameOrigin()));
//		http.csrf(csrf->csrf.disable());
//		
//		return http.build();
//	}
	
	
//	This is used to store multiple user but in this case, taking two obj one is user and other is admin.
//  And storing them in memory only So will return InMemoryUserDetailsManager	
// Both Objects should be of type UserDetails	
	
	
//	@Bean 
//	UserDetailsService detailsService() {
////		{noop} tells password should be store in plain text form
//		UserDetails user1 = User.withUsername("user1").password("{noop}user1pass").roles("USER").build();
//		UserDetails admin = User.withUsername("admin").password("{noop}adminpass").roles("ADMIN").build();
//		return new InMemoryUserDetailsManager(user1,admin);
//	}
	
	
	//Now Using JdbcUserDetailsManger to store user which takes a dataSource obj
	// It store user in database and our database is in memory h2 database so we need schema also because it create schema every time it runs
//	@Bean 
//	UserDetailsService detailsService() {
//		UserDetails user1 = User.withUsername("user1").password(passwordEncoder().encode("user1pass")).roles("USER").build();
//		UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("adminpass")).roles("ADMIN").build();
//		
//		JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
//		userDetailsManager.createUser(user1);
//		userDetailsManager.createUser(admin);
//		return userDetailsManager;
//		
//	}
	
	//For Password Encoding creating bean
//	@Bean
//	PasswordEncoder passwordEncoder() {
//		return new BCryptPasswordEncoder();
//	}
	
	
	
	
	// JWT Security Configuration
	
	@Bean
	AuthTokenFilter authTokenFilter() {
		return new AuthTokenFilter();
	};
	
	@Autowired
	AuthEntryPointJwt unauthorizedHandler;
	
	SecurityFilterChain getfilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(req->req
				.requestMatchers("/h2-console/**").permitAll()
				.requestMatchers("/signin").permitAll()
				.anyRequest().authenticated());
		http.sessionManagement(session->session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.exceptionHandling(exception->exception.authenticationEntryPoint(unauthorizedHandler));
		http.headers(headers->headers
				.frameOptions(frameOptions->frameOptions.sameOrigin()));
		http.csrf(csrf->csrf.disable());
		http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
		
		
		return http.build();
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}
	
	@Bean 
	UserDetailsService userDetailsService() {
		return new JdbcUserDetailsManager(dataSource);	
	}
	
	@Bean
	public CommandLineRunner initData(UserDetailsService userDetailsService) {
		return args->{
			JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
			UserDetails user1 = User.withUsername("user1").password(passwordEncoder().encode("user1pass")).roles("USER").build();
			UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("adminpass")).roles("ADMIN").build();
			
			JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
			userDetailsManager.createUser(user1);
			userDetailsManager.createUser(admin);
		};
	}

}
