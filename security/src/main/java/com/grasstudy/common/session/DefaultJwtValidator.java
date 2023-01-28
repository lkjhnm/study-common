package com.grasstudy.common.session;

import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

@Component
public class DefaultJwtValidator implements PkiBasedValidator<Claims>, SigningKeyResolver {

	private final Map<String, PublicKey> publicKeys = new HashMap<>();

	private final JwtParser parser = Jwts.parserBuilder().setSigningKeyResolver(this).build();

	@Override
	public void addPublicKeys(Map<String, PublicKey> publicKeys) {
		this.publicKeys.putAll(publicKeys);
	}

	@Override
	public Key resolveSigningKey(JwsHeader header, Claims claims) {
		return getKey(header);
	}

	@Override
	public Key resolveSigningKey(JwsHeader header, String plaintext) {
		return getKey(header);
	}

	private PublicKey getKey(JwsHeader header) {
		//todo: lock to process when add PublicKeys
		PublicKey publicKey = this.publicKeys.get(header.getKeyId());
		if (publicKey == null) {
			throw new JwtException(String.format("No such public-key from given kid [%s]", header.getKeyId()));
		}
		return publicKey;
	}

	@Override
	public Claims validate(String token) {
		return parser.parseClaimsJws(token).getBody();
	}
}
