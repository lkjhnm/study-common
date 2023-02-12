package com.grasstudy.common.security.reactive;


import com.grasstudy.common.security.JwtAuthentication;
import com.grasstudy.common.session.AuthenticationValidator;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

	private final AuthenticationValidator<Claims> validator;

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.just(authentication).filter(JwtAuthentication.class::isInstance)
		           .map(this::getCredentials)
		           .map(credentials -> {
			           JwtAuthentication jwtAuthentication = new JwtAuthentication(credentials, validator.validate(credentials));
			           jwtAuthentication.setAuthenticated(true);
			           return (Authentication) jwtAuthentication;
		           }).defaultIfEmpty(authentication);

	}

	private String getCredentials(Authentication authentication) {
		return (String) authentication.getCredentials();
	}
}
