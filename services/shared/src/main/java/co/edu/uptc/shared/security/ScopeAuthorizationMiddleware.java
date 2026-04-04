package co.edu.uptc.shared.security;

import java.util.Collection;
import java.util.Set;

public final class ScopeAuthorizationMiddleware {

    public boolean isAllowed(Set<String> grantedScopes, Collection<String> requiredScopes) {
        if (requiredScopes == null || requiredScopes.isEmpty()) {
            return true;
        }

        if (grantedScopes == null || grantedScopes.isEmpty()) {
            return false;
        }

        for (String requiredScope : requiredScopes) {
            if (grantedScopes.contains(requiredScope)) {
                return true;
            }
        }

        return false;
    }
}