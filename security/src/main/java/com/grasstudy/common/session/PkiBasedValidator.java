package com.grasstudy.common.session;

import java.security.PublicKey;
import java.util.Map;

public interface PkiBasedValidator<T> extends TokenValidator<T> {

	void addPublicKeys(Map<String, PublicKey> publicKeys);
}
