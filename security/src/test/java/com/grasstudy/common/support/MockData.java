package com.grasstudy.common.support;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class MockData {

	public static KeyPair pairA = Keys.keyPairFor(SignatureAlgorithm.ES256);
	public static KeyPair pairB = Keys.keyPairFor(SignatureAlgorithm.ES256);

	public static String jwtToken(String kid, KeyPair keyPair) {
		return Jwts.builder()
		           .setHeaderParam("kid", kid)
		           .signWith(keyPair.getPrivate())
		           .setExpiration(Date.from(LocalDateTime.now().plusHours(1).atZone(ZoneId.systemDefault())
		                                                 .toInstant()))
		           .setIssuedAt(new Date())
		           .compact();
	}
}
