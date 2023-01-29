package com.grasstudy.common.security.reactive;

import com.grasstudy.common.security.JwtAuthentication;
import com.grasstudy.common.session.PkiBasedJwtValidator;
import com.grasstudy.common.session.PkiBasedValidator;
import com.grasstudy.common.support.MockData;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import reactor.test.StepVerifier;

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

	PkiBasedValidator<Claims> validator() {
		PkiBasedJwtValidator pkiBasedJwtValidator = new PkiBasedJwtValidator();
		pkiBasedJwtValidator.setPublicKeys(Map.of("pairA", MockData.pairA.getPublic()));
		return pkiBasedJwtValidator;
	}
}
