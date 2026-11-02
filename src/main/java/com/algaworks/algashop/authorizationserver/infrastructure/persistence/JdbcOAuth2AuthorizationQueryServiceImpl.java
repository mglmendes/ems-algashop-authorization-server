package com.algaworks.algashop.authorizationserver.infrastructure.persistence;

import com.algaworks.algashop.authorizationserver.infrastructure.security.persisntence.OAuth2AuthorizationQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class JdbcOAuth2AuthorizationQueryServiceImpl implements OAuth2AuthorizationQueryService {

    private final JdbcOperations jdbcOperations;
    private final static String SQL = "SELECT id FROM oauth2_authorization WHERE principal_name = ?";
    @Override
    public List<String> findAuthorizationIds(String principalName) {
        return jdbcOperations.queryForList(SQL, String.class, principalName);
    }
}
