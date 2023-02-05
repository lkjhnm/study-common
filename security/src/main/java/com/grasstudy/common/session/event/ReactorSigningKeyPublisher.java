package com.grasstudy.common.session.event;

import com.grasstudy.common.session.event.scheme.SigningKeyCreateEvent;
import reactor.core.publisher.Flux;

import java.util.function.Consumer;
import java.util.function.Supplier;

public class ReactorSigningKeyPublisher implements SigningKeyPublisher<Flux<SigningKeyCreateEvent>> {

	private final Flux<SigningKeyCreateEvent> createEventFlux;

	private Consumer<SigningKeyCreateEvent> createEventConsumer;

	public ReactorSigningKeyPublisher() {
		this.createEventFlux = Flux.create(emitter -> createEventConsumer = emitter::next);
	}

	@Override
	public void publish(SigningKeyCreateEvent createEvent) {
		this.createEventConsumer.accept(createEvent);
	}

	@Override
	public Supplier<Flux<SigningKeyCreateEvent>> publisher() {
		return () -> this.createEventFlux;
	}
}
