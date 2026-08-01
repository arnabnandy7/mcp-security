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

import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR;

/**
 * Validates authorization code request redirect URIs, allowing the port to vary when both
 * the requested and registered redirect URI use the {@code localhost} host.
 * <p>
 * <strong>WARNING:</strong> OAuth 2.1 does not recommend using {@code localhost} for
 * loopback redirection. Some clients use it, however, and require this compatibility
 * behavior. Requests that do not qualify for localhost wildcard port matching are
 * delegated to Spring Authorization Server's default redirect URI validator.
 *
 * @author Arnab Nandy
 * @see <a href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.html#section-8.4.2">OAuth
 * 2.1, Loopback Interface Redirection</a>
 */
public final class LocalhostWildcardPortValidator
		implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

	private static final String LOCALHOST = "localhost";

	@Override
	public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = context.getAuthentication();
		@Nullable String requestedRedirectUri = authentication.getRedirectUri();
		@Nullable UriComponents requested = parseLocalhostRedirectUri(requestedRedirectUri);
		if (requested != null && context.getRegisteredClient()
			.getRedirectUris()
			.stream()
			.anyMatch(registeredRedirectUri -> matchesExceptPort(requested, registeredRedirectUri))) {
			return;
		}
		DEFAULT_REDIRECT_URI_VALIDATOR.accept(context);
	}

	@Nullable private static UriComponents parseLocalhostRedirectUri(@Nullable String redirectUri) {
		if (redirectUri == null) {
			return null;
		}
		try {
			UriComponents uri = UriComponentsBuilder.fromUriString(redirectUri).build();
			return LOCALHOST.equalsIgnoreCase(uri.getHost()) ? uri : null;
		}
		catch (IllegalArgumentException ex) {
			return null;
		}
	}

	private static boolean matchesExceptPort(UriComponents requested, String registeredRedirectUri) {
		try {
			UriComponentsBuilder registered = UriComponentsBuilder.fromUriString(registeredRedirectUri);
			registered.port(requested.getPort());
			return registered.build().toString().equals(requested.toString());
		}
		catch (IllegalArgumentException ex) {
			return false;
		}
	}

}
