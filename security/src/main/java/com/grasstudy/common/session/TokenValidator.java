package com.grasstudy.common.session;

public interface TokenValidator<T> {
	T validate(String token);
}
