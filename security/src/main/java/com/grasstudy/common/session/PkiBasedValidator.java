package com.grasstudy.common.session;

import java.security.PublicKey;
import java.util.Map;

public interface PkiBasedValidator<T> extends AuthenticationValidator<T> {

	void setPublicKeys(Map<String, PublicKey> publicKeys);

	PublicKey getPublicKey(String kid);
}
