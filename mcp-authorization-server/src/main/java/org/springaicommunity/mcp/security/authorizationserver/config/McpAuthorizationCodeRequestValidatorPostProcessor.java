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

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;

/**
 * Post-processor to set the authorization code request validator on
 * {@link OAuth2AuthorizationCodeRequestAuthenticationProvider}.
 * <p>
 * For internal use only.
 *
 * @author Arnab Nandy
 */
class McpAuthorizationCodeRequestValidatorPostProcessor
		implements ObjectPostProcessor<OAuth2AuthorizationCodeRequestAuthenticationProvider> {

	private final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> validator;

	McpAuthorizationCodeRequestValidatorPostProcessor(
			Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> validator) {
		this.validator = validator;
	}

	@Override
	public OAuth2AuthorizationCodeRequestAuthenticationProvider postProcess(
			OAuth2AuthorizationCodeRequestAuthenticationProvider object) {
		object.setAuthenticationValidator(this.validator);
		return object;
	}

}
