package com.grasstudy.common.session;


import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Map;


class DefaultJwtValidatorTest {

	@Test
	void validate() {
		KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
		String kid = "test";
		String jwtToken = generateToken(keyPair, kid);

		DefaultJwtValidator jwtValidator = new DefaultJwtValidator();
		jwtValidator.setPublicKeys(Map.of(kid, keyPair.getPublic()));
		jwtValidator.validate(jwtToken);
	}

	@Test
	void validate_failure() {
		KeyPair rightPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
		KeyPair wrongPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
		String kid = "test";
		String testToken = generateToken(rightPair, kid);

		DefaultJwtValidator jwtValidator = new DefaultJwtValidator();
		jwtValidator.setPublicKeys(Map.of(kid, wrongPair.getPublic()));
		Assertions.assertThrows(JwtException.class, () -> jwtValidator.validate(testToken));
	}


	private String generateToken(KeyPair keyPair, String kid) {
		return Jwts.builder()
		           .setHeaderParam("kid", kid)
		           .signWith(keyPair.getPrivate())
		           .setExpiration(Date.from(LocalDateTime.now().plusHours(1).atZone(ZoneId.systemDefault())
		                                                 .toInstant()))
		           .setIssuedAt(new Date())
		           .compact();
	}
}