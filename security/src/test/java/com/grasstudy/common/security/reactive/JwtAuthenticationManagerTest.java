package com.grasstudy.common.security.reactive;

import com.grasstudy.common.security.JwtAuthentication;
import com.grasstudy.common.session.PkiBasedJwtValidator;
import com.grasstudy.common.session.PkiBasedValidator;
import com.grasstudy.common.support.MockData;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.List;
import java.util.Map;

class JwtAuthenticationManagerTest {

	@Test
	void authenticate() {
		String jwtToken = MockData.jwtToken("pairA", MockData.pairA);
		JwtAuthenticationManager manager = new JwtAuthenticationManager(validator());
		manager.authenticate(new JwtAuthentication(jwtToken))
		       .as(StepVerifier::create)
		       .expectNextMatches(Authentication::isAuthenticated)
		       .verifyComplete();
	}

	@Test
	void authenticate_failure() {
		String invalidToken = MockData.jwtToken("pairA", MockData.pairB);
		JwtAuthenticationManager manager = new JwtAuthenticationManager(validator());
		manager.authenticate(new JwtAuthentication(invalidToken))
		       .as(StepVerifier::create)
		       .expectError(JwtException.class)
		       .verify();
	}

	@Test
	void authenticate_empty() {
		JwtAuthenticationManager manager = new JwtAuthenticationManager(validator());
		AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("test", "test",
				AuthorityUtils.createAuthorityList("ANONYMOUS"));
		anonymous.setAuthenticated(false);
		manager.authenticate(
				       anonymous)
		       .as(StepVerifier::create)
		       .expectNextMatches(authentication ->
				       !authentication.isAuthenticated() && authentication.equals(anonymous))
		       .verifyComplete();
	}

	PkiBasedValidator<Claims> validator() {
		PkiBasedJwtValidator pkiBasedJwtValidator = new PkiBasedJwtValidator();
		pkiBasedJwtValidator.setSigningKeys(Map.of("pairA", MockData.pairA.getPublic()));
		return pkiBasedJwtValidator;
	}
}
