package com.grasstudy.common.security;

import io.jsonwebtoken.Claims;
import lombok.Data;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

@Data
public class JwtAuthentication implements Authentication {

	private final String token;
	private boolean authenticated = false;
	private Claims claims;

	public JwtAuthentication(String token) {
		this.token = token;
	}

	public JwtAuthentication(String token, Claims claims) {
		this.token = token;
		this.claims = claims;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.emptyList();
	}

	@Override
	public Object getCredentials() {
		return token;
	}

	@Override
	public Object getDetails() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return this.claims;
	}

	@Override
	public boolean isAuthenticated() {
		return this.authenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		this.authenticated = isAuthenticated;
	}

	@Override
	public String getName() {
		//todo: claimName move to constants
		return this.authenticated ? this.claims.get("userId", String.class) : null;
	}
}
