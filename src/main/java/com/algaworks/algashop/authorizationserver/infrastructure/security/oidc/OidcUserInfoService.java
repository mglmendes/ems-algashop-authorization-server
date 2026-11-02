package com.algaworks.algashop.authorizationserver.infrastructure.security.oidc;

import com.algaworks.algashop.authorizationserver.domain.model.AuthUser;
import com.algaworks.algashop.authorizationserver.domain.model.AuthUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OidcUserInfoService {

    private final AuthUserRepository authUserRepository;

    public OidcUserInfo loadUser(String email) {
        AuthUser authUser = authUserRepository.findByEmail(email).orElseThrow(
                () -> new UsernameNotFoundException("user %s not found".formatted(email))
        );

        return OidcUserInfo.builder()
                .name(authUser.getName())
                .email(authUser.getEmail())
                .subject(authUser.getId().toString())
                .claim("type", authUser.getType().name())
                .claim("created_at", String.valueOf(authUser.getCreatedAt().toEpochSecond()))
                .build();
    }
}
