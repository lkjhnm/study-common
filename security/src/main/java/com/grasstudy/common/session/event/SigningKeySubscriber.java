package com.grasstudy.common.session.event;

import com.grasstudy.common.session.PkiBasedValidator;
import com.grasstudy.common.session.event.scheme.SigningKeyCreateEvent;

import java.util.function.Consumer;

public interface SigningKeySubscriber<T> {
	Consumer<T> subscriber(PkiBasedValidator<?> pkiBasedValidator);
}
