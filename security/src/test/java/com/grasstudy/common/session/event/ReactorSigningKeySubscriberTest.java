package com.grasstudy.common.session.event;

import com.grasstudy.common.session.PkiBasedJwtValidator;
import com.grasstudy.common.session.PkiBasedValidator;
import com.grasstudy.common.session.event.scheme.SigningKeyCreateEvent;
import com.grasstudy.common.support.MockData;
import io.jsonwebtoken.Claims;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.cloud.stream.binder.test.InputDestination;
import org.springframework.cloud.stream.binder.test.OutputDestination;
import org.springframework.cloud.stream.binder.test.TestChannelBinderConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.converter.CompositeMessageConverter;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import reactor.core.publisher.Flux;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.function.Consumer;
import java.util.function.Supplier;

@ExtendWith(SpringExtension.class)
@Import({TestChannelBinderConfiguration.class, ReactorSigningKeySubscriberTest.EventConfiguration.class})
class ReactorSigningKeySubscriberTest {

	@Configuration
	@EnableAutoConfiguration
	static class EventConfiguration {

		@Bean
		PkiBasedValidator<Claims> pkiBasedValidator() {
			return new PkiBasedJwtValidator();
		}

		@Bean
		Consumer<Flux<SigningKeyCreateEvent>> signingKeyConsumer(PkiBasedValidator<?> pkiBasedValidator) {
			return new ReactorSigningKeySubscriber().subscriber(pkiBasedValidator);
		}
	}

	@Autowired
	InputDestination inputDestination;

	@Autowired
	CompositeMessageConverter compositeMessageConverter;

	@Autowired
	PkiBasedValidator<Claims> pkiBasedValidator;

	@Test
	void subscriber() {
		KeyPair signingKey = MockData.pairA;
		String kid = "test";
		PublicKey publicKey = signingKey.getPublic();

		SigningKeyCreateEvent event = SigningKeyCreateEvent.builder()
		                                                   .kid(kid)
		                                                   .algorithm(publicKey.getAlgorithm())
		                                                   .publicKey(publicKey.getEncoded())
		                                                   .build();
		Message<?> message = new GenericMessage<>(event);
		inputDestination.send(message, "signingKeyConsumer-in-0");
		// todo: 시점 문제없나...?
		Assertions.assertThat(pkiBasedValidator.getPublicKey(kid)).isNotNull();
	}
}