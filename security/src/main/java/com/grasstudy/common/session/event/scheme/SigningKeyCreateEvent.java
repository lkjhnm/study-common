package com.grasstudy.common.session.event.scheme;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SigningKeyCreateEvent {

	private String kid;
	private String algorithm;
	private byte[] publicKey;
}
