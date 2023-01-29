package com.grasstudy.common.security.reactive;

import com.grasstudy.common.security.JwtAuthentication;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class JwtAuthenticationFilter implements WebFilter {

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext().switchIfEmpty(Mono.defer(() -> {
            Authentication authentication = createAuthentication(exchange);
            SecurityContext securityContext = new SecurityContextImpl(authentication);
            return chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)))
                        .then(Mono.empty());
            }))
            .flatMap((alreadyCreated) -> chain.filter(exchange));
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
