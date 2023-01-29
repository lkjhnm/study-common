package com.grasstudy.common.session;

public interface AuthenticationValidator<T> {
	T validate(String token);
}
