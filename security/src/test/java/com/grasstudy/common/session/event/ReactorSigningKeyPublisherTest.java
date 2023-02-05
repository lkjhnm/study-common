package com.grasstudy.common.session.event;

import com.grasstudy.common.session.event.scheme.SigningKeyCreateEvent;
import com.grasstudy.common.support.MockData;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.cloud.stream.binder.test.OutputDestination;
import org.springframework.cloud.stream.binder.test.TestChannelBinderConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.messaging.Message;
import org.springframework.messaging.converter.CompositeMessageConverter;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import reactor.core.publisher.Flux;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.function.Supplier;

@ExtendWith(SpringExtension.class)
@Import({TestChannelBinderConfiguration.class, ReactorSigningKeyPublisherTest.EventConfiguration.class})
class ReactorSigningKeyPublisherTest {

	@Configuration
	@EnableAutoConfiguration
	static class EventConfiguration {

		@Bean
		public SigningKeyPublisher<Flux<SigningKeyCreateEvent>> singingKeyPublisher() {
			return new ReactorSigningKeyPublisher();
		}

		@Bean
		Supplier<Flux<SigningKeyCreateEvent>> signingKeySupplier(
				SigningKeyPublisher<Flux<SigningKeyCreateEvent>> signingKeyPublisher) {
			return signingKeyPublisher.publisher();
		}
	}

	@Autowired
	SigningKeyPublisher<Flux<SigningKeyCreateEvent>> signingKeyPublisher;

	@Autowired
	OutputDestination outputDestination;

	@Autowired
	CompositeMessageConverter compositeMessageConverter;

	@Test
	void publish() {
		KeyPair signingKey = MockData.pairA;
		String kid = "test";
		PublicKey publicKey = signingKey.getPublic();

		signingKeyPublisher.publish(SigningKeyCreateEvent.builder()
		                                                 .kid(kid)
		                                                 .algorithm(publicKey.getAlgorithm())
		                                                 .publicKey(publicKey.getEncoded())
		                                                 .build());

		Message<byte[]> receive = outputDestination.receive(1000, "signingKeySupplier-out-0");
		Assertions.assertThat(receive).isNotNull();
		SigningKeyCreateEvent event = (SigningKeyCreateEvent) compositeMessageConverter.fromMessage(receive, SigningKeyCreateEvent.class);
		Assertions.assertThat(event.getPublicKey()).isEqualTo(publicKey.getEncoded());
		Assertions.assertThat(event.getAlgorithm()).isEqualTo(publicKey.getAlgorithm());
		Assertions.assertThat(event.getKid()).isEqualTo(kid);
	}

}