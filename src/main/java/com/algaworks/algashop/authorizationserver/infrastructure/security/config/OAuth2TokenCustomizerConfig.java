package com.algaworks.algashop.authorizationserver.infrastructure.security.config;

import com.algaworks.algashop.authorizationserver.infrastructure.security.OidcUserInfoService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class OAuth2TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(OidcUserInfoService oidcUserService) {
        return context -> {
            if (OidcParameterNames.ID_TOKEN.equalsIgnoreCase(context.getTokenType().getValue())) {
                String email = context.getPrincipal().getName();
                OidcUserInfo oidcUserInfo = oidcUserService.loadUser(email);
                context.getClaims().claims(
                        claims -> claims.putAll(oidcUserInfo.getClaims())
                );
            }
        };
    }
}
