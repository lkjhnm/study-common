package com.grasstudy.common.session.event;

import com.grasstudy.common.session.event.scheme.SigningKeyCreateEvent;

import java.util.function.Supplier;

public interface SigningKeyPublisher<T> {

	void publish(SigningKeyCreateEvent createEvent);

	Supplier<T> publisher();
}
