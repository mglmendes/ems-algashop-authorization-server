package com.algaworks.algashop.authorizationserver.infrastructure.security.token;

import com.algaworks.algashop.authorizationserver.infrastructure.security.oidc.OidcUserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
@RequiredArgsConstructor
public class OAuth2TokenCustomizerConfig {

    private final OidcUserInfoService oidcUserService;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (isIdToken(context.getTokenType())) {
                OidcUserInfo oidcUserInfo = loadUser(context);
                context.getClaims().claims(
                        claims -> claims.putAll(oidcUserInfo.getClaims())
                );
            } else if (isAccessToken(context.getTokenType()) &&
                    isAuthCodeFlow(context.getAuthorizationGrantType()) ||
                    isRefreshTokenFlow(context.getAuthorizationGrantType())) {
                OidcUserInfo oidcUserInfo = loadUser(context);
                context.getClaims().subject(oidcUserInfo.getSubject());
            }
        };
    }

    private boolean isRefreshTokenFlow(AuthorizationGrantType authorizationGrantType) {
        return AuthorizationGrantType.REFRESH_TOKEN.equals(authorizationGrantType);
    }

    private boolean isAuthCodeFlow(AuthorizationGrantType authorizationGrantType) {
        return AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType);
    }

    private OidcUserInfo loadUser(JwtEncodingContext context) {
        String email = context.getPrincipal().getName();
        return oidcUserService.loadUser(email);
    }

    private boolean isIdToken(OAuth2TokenType tokenType) {
        return OidcParameterNames.ID_TOKEN.equals(tokenType.getValue());
    }

    private static boolean isAccessToken(OAuth2TokenType tokenType) {
        return OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue());
    }
}
