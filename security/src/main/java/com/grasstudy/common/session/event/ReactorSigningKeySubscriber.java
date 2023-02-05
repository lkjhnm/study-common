package com.grasstudy.common.session.event;

import com.grasstudy.common.session.PkiBasedValidator;
import com.grasstudy.common.session.event.scheme.SigningKeyCreateEvent;
import reactor.core.publisher.Flux;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class ReactorSigningKeySubscriber implements SigningKeySubscriber<Flux<SigningKeyCreateEvent>> {

	private final Map<String, KeyFactory> keyFactoryMap = new HashMap<>();

	public Consumer<Flux<SigningKeyCreateEvent>> subscriber(PkiBasedValidator<?> pkiBasedValidator) {
		return input ->
				input.subscribe(createEvent -> pkiBasedValidator.setSigningKeys(
				Map.of(createEvent.getKid(), toPublicKey(createEvent.getAlgorithm(), createEvent.getPublicKey()))
		));
	}

	PublicKey toPublicKey(String algorithm, byte[] encoded) {
		KeyFactory keyFactory = keyFactory(algorithm);
		try {
			// todo: ES256 알고리즘에 종속적인 코드인가?
			return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	KeyFactory keyFactory(String algorithm) {
		synchronized (keyFactoryMap) {
			try {
				KeyFactory keyFactory = keyFactoryMap.putIfAbsent(algorithm, KeyFactory.getInstance(algorithm));
				return keyFactory == null ? keyFactoryMap.get(algorithm) : keyFactory;
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
		}
	}
}
