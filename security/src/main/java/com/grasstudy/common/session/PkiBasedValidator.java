package com.grasstudy.common.session;

import java.security.PublicKey;
import java.util.Map;

public interface PkiBasedValidator<T> extends AuthenticationValidator<T> {

	void setSigningKeys(Map<String, PublicKey> signingKeys);

	PublicKey getPublicKey(String kid);
}
