package com.grasstudy.common.security.reactive;

import com.grasstudy.common.security.JwtAuthentication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JwtAuthenticationConverter implements ServerAuthenticationConverter {

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		return Mono.just(createAuthentication(exchange));
	}

	private Authentication createAuthentication(ServerWebExchange exchange) {
		return new JwtAuthentication(resolveToken(exchange.getRequest()));
	}

	private String resolveToken(ServerHttpRequest httpRequest) {
		String authorization = httpRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (authorization != null) {
			int index = authorization.indexOf(" ");
			return authorization.substring(index + 1);
		} else {
			return null;
		}
	}
}
