package org.springaicommunity.mcp.security.client.sync.oauth2.registration;

public enum OidcApplicationType {

	WEB("web"), NATIVE("native");

	private final String type;

	OidcApplicationType(String type) {
		this.type = type;
	}

	@Override
	public String toString() {
		return type;
	}

}
