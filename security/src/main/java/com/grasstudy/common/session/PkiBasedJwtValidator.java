package com.grasstudy.common.session;

import io.jsonwebtoken.*;

import java.security.Key;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class PkiBasedJwtValidator implements PkiBasedValidator<Claims>, SigningKeyResolver {

	private final Map<String, PublicKey> publicKeys = new HashMap<>();

	private final JwtParser parser = Jwts.parserBuilder().setSigningKeyResolver(this).build();

	@Override
	public void setPublicKeys(Map<String, PublicKey> publicKeys) {
		this.publicKeys.putAll(publicKeys);
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
		PublicKey publicKey = this.publicKeys.get(kid);
		if (publicKey == null) {
			throw new JwtException(String.format("No such public-key from given kid [%s]", kid));
		}
		return publicKey;
	}

	@Override
	public Claims validate(String token) {
		return parser.parseClaimsJws(token).getBody();
	}
}
