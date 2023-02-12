package com.grasstudy.common.security.reactive;


import com.grasstudy.common.security.JwtAuthentication;
import com.grasstudy.common.session.AuthenticationValidator;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

import java.util.Objects;
import java.util.logging.Level;

@RequiredArgsConstructor
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

	private final AuthenticationValidator<Claims> validator;

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.just(authentication).filter(JwtAuthentication.class::isInstance)
		           .map(this::getCredentials)
		           .filter(v -> !v.isEmpty())
		           .map(credentials -> {
			           JwtAuthentication jwtAuthentication = new JwtAuthentication(credentials, validator.validate(credentials));
			           jwtAuthentication.setAuthenticated(true);
			           return (Authentication) jwtAuthentication;
		           }).switchIfEmpty(Mono.error(new AuthenticationServiceException("Authentication is empty")));

	}

	private String getCredentials(Authentication authentication) {
		Object credentials = authentication.getCredentials();
		return Objects.isNull(credentials) ? "" : (String) credentials;
	}
}
