package co.edu.uptc.shared.security;

import io.jsonwebtoken.Claims;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

public final class JwtScopeExtractor {

    public static final String SCOPES_CLAIM = "scopes";

    private JwtScopeExtractor() {
    }

    public static Set<String> extractScopes(Claims claims) {
        if (claims == null) {
            return Set.of();
        }

        return extractScopes(claims.get(SCOPES_CLAIM));
    }

    public static Set<String> extractScopes(Object rawScopes) {
        if (rawScopes instanceof Collection<?> collection) {
            Set<String> scopes = new LinkedHashSet<>();
            for (Object scope : collection) {
                if (scope != null) {
                    String value = scope.toString().trim();
                    if (!value.isBlank()) {
                        scopes.add(value);
                    }
                }
            }
            return Set.copyOf(scopes);
        }

        if (rawScopes instanceof String scopeValue) {
            String trimmed = scopeValue.trim();
            if (!trimmed.isBlank()) {
                return Set.of(trimmed);
            }
        }

        return Set.of();
    }
}