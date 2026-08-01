/*
 * Copyright 2026-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.mock;

class LocalhostWildcardPortValidatorTests {

	private final LocalhostWildcardPortValidator validator = new LocalhostWildcardPortValidator();

	@Test
	void allowsDifferentPortForLocalhost() {
		var context = context("http://localhost:54321/callback", "http://localhost:8080/callback");

		assertThatNoException().isThrownBy(() -> this.validator.accept(context));
	}

	@Test
	void allowsImplicitDefaultPortForLocalhost() {
		var context = context("http://localhost/callback", "http://localhost:8080/callback");

		assertThatNoException().isThrownBy(() -> this.validator.accept(context));
	}

	@Test
	void rejectsDifferentPathForLocalhost() {
		var context = context("http://localhost:54321/other-callback", "http://localhost:8080/callback");

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.validator.accept(context));
	}

	@Test
	void delegatesNonLocalhostRedirectUriToDefaultValidator() {
		var context = context("https://example.com/callback", "https://registered.example.com/callback");

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.validator.accept(context));
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationContext context(String requestedRedirectUri,
			String registeredRedirectUri) {
		Authentication principal = mock(Authentication.class);
		var authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://authorization-server.test",
				"client-id", principal, requestedRedirectUri, "state", Set.of(), Map.of());
		var registeredClient = RegisteredClient.withId("client-id")
			.clientId("client-id")
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(registeredRedirectUri)
			.build();
		return OAuth2AuthorizationCodeRequestAuthenticationContext.with(authentication)
			.registeredClient(registeredClient)
			.build();
	}

}
