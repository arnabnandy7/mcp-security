package org.springaicommunity.mcp.security.client.sync.oauth2.registration;

import java.util.List;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.test.json.JsonContent;
import org.springframework.test.json.JsonContentAssert;

class DynamicClientRegistrationRequestTest {

	@Test
	void serializes() {
		var request = DynamicClientRegistrationRequest.builder()
			.applicationType(OidcApplicationType.NATIVE)
			.clientName("test-client")
			.clientUri("https://client.example.com")
			.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.AUTHORIZATION_CODE))
			.redirectUris(List.of("https://client.example.com/oauth2/callback"))
			.responseTypes(List.of(OAuth2AuthorizationResponseType.CODE, new OAuth2AuthorizationResponseType("CUSTOM")))
			.scope(List.of("message.read", "message.write"))
			.tokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
			.build();

		var serializedRequest = JsonMapper.builder()
			.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
			.build()
			.writeValueAsString(request);

		new JsonContentAssert(new JsonContent(serializedRequest)).isLenientlyEqualTo("""
				{
				  "application_type": "native",
				  "client_name": "test-client",
				  "client_uri": "https://client.example.com",
				  "grant_types": [
				    "client_credentials",
				    "authorization_code"
				  ],
				  "redirect_uris": [
				    "https://client.example.com/oauth2/callback"
				  ],
				  "response_types": [
				    "code",
				    "CUSTOM"
				  ],
				  "scope": "message.read message.write",
				  "token_endpoint_auth_method": "client_secret_post"
				}
				""");
	}

}
