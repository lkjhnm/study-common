package com.grasstudy.common.session;


import com.grasstudy.common.support.MockData;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Map;


class PkiBasedJwtValidatorTest {

	@Test
	void validate() {
		KeyPair keyPair = MockData.pairA;
		String kid = "test";
		String jwtToken = MockData.jwtToken(kid, keyPair);

		PkiBasedJwtValidator jwtValidator = new PkiBasedJwtValidator();
		jwtValidator.setSigningKeys(Map.of(kid, keyPair.getPublic()));
		jwtValidator.validate(jwtToken);
	}

	@Test
	void validate_failure() {
		KeyPair rightPair = MockData.pairA;
		KeyPair wrongPair = MockData.pairB;
		String kid = "test";
		String testToken = MockData.jwtToken(kid, rightPair);

		PkiBasedJwtValidator jwtValidator = new PkiBasedJwtValidator();
		jwtValidator.setSigningKeys(Map.of(kid, wrongPair.getPublic()));
		Assertions.assertThrows(JwtException.class, () -> jwtValidator.validate(testToken));
	}
}