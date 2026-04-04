package co.edu.uptc.shared.security;

import co.edu.uptc.shared.security.annotations.RequiresScope;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Interceptor que valida el scope declarado en {@link RequiresScope}
 * contra el header {@code X-Scopes} inyectado por el API-Gateway.
 *
 * <p>Flujo:</p>
 * <ol>
 *   <li>Si el handler no está anotado con {@code @RequiresScope} → pasa.</li>
 *   <li>Lee {@code X-Scopes} (lista separada por comas).</li>
 *   <li>Si el scope requerido está en la lista → pasa.</li>
 *   <li>Si no → {@code 403 Forbidden}.</li>
 * </ol>
 */
public class ScopeInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(ScopeInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws IOException {

        // Solo aplica a métodos de controller, no a recursos estáticos
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }

        RequiresScope annotation = method.getMethodAnnotation(RequiresScope.class);

        // Sin anotación → no hay restricción adicional de scope
        if (annotation == null) {
            return true;
        }

        String required = annotation.value();
        List<String> userScopes = parseScopes(request.getHeader(GatewayAuthFilter.SCOPES_HEADER));

        if (userScopes.contains(required)) {
            return true;
        }

        log.warn("[ScopeInterceptor] User '{}' lacks scope '{}' for {} {}",
                request.getHeader(GatewayAuthFilter.USER_HEADER),
                required,
                request.getMethod(),
                request.getRequestURI());

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("""
                {"error":"Forbidden","message":"Required scope: %s"}
                """.formatted(required));

        return false; // corta la cadena, el controller no se ejecuta
    }

    // -------------------------------------------------------------------------

    private List<String> parseScopes(String scopesHeader) {
        if (scopesHeader == null || scopesHeader.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.stream(scopesHeader.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}