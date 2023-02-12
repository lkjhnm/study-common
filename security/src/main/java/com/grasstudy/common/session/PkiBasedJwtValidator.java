package com.grasstudy.common.session;

import io.jsonwebtoken.*;
import org.springframework.security.authentication.AuthenticationServiceException;

import java.security.Key;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class PkiBasedJwtValidator implements PkiBasedValidator<Claims>, SigningKeyResolver {

	private final Map<String, PublicKey> signingKeys = new HashMap<>();

	private final JwtParser parser = Jwts.parserBuilder().setSigningKeyResolver(this).build();

	@Override
	public void setSigningKeys(Map<String, PublicKey> signingKeys) {
		this.signingKeys.putAll(signingKeys);
	}

	@Override
	public Key resolveSigningKey(JwsHeader header, Claims claims) {
		return getPublicKey(header.getKeyId());
	}

	@Override
	public Key resolveSigningKey(JwsHeader header, String plaintext) {
		return getPublicKey(header.getKeyId());
	}

	@Override
	public PublicKey getPublicKey(String kid) {
		PublicKey publicKey = this.signingKeys.get(kid);
		if (publicKey == null) {
			throw new JwtException(String.format("No such public-key from given kid [%s]", kid));
		}
		return publicKey;
	}

	@Override
	public Claims validate(String token) {
		try {
			return parser.parseClaimsJws(token).getBody();
		} catch (JwtException e) {
			throw new AuthenticationServiceException(e.getLocalizedMessage(), e);
		}
	}
}
