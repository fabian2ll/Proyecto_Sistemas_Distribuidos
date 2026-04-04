package co.edu.uptc.shared.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Servlet filter (Spring MVC / Spring Boot standard) that protects every
 * microservice endpoint by verifying two invariants:
 *
 * <ol>
 *   <li>The request carries the {@code X-Gateway-Secret} header whose value
 *       matches the shared secret configured via {@code gateway.secret}.</li>
 *   <li>The request carries the {@code X-User} header injected by the
 *       API-Gateway after a successful JWT validation.</li>
 * </ol>
 *
 * <p>If either check fails the filter short-circuits with
 * {@code 403 Forbidden} and writes a plain-text reason so downstream
 * troubleshooting is straightforward without leaking security details.</p>
 *
 * <h2>Registration</h2>
 * {@link GatewayAuthAutoConfiguration} registers this filter automatically
 * for every Spring Boot microservice that includes the {@code shared} module.
 * No extra {@code @Bean} declaration is needed in each service.
 *
 * <h2>Public paths</h2>
 * Paths that must bypass the filter (e.g. {@code /actuator/**}) are listed in
 * {@link #isPublicPath(String)}.  Extend that method or override the bean in
 * the individual service if you need service-specific exemptions.
 */
public class GatewayAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(GatewayAuthFilter.class);

    /** Header injected by the API-Gateway carrying the shared secret. */
    public static final String GATEWAY_SECRET_HEADER = "X-Gateway-Secret";

    /** Header injected by the API-Gateway after JWT validation (JWT subject). */
    public static final String USER_HEADER = "X-User";

    /** Header injected by the API-Gateway with the comma-separated scopes. */
    public static final String SCOPES_HEADER = "X-Scopes";

    private final GatewayAuthProperties properties;

    public GatewayAuthFilter(GatewayAuthProperties properties) {
        this.properties = properties;
    }

    // -------------------------------------------------------------------------
    // Core filter logic
    // -------------------------------------------------------------------------

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        if (isPublicPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 1. Validate gateway secret -------------------------------------------
        String gatewaySecret = request.getHeader(GATEWAY_SECRET_HEADER);

        if (gatewaySecret == null || gatewaySecret.isBlank()) {
            log.warn("Rejected request to '{}': missing {} header", path, GATEWAY_SECRET_HEADER);
            sendForbidden(response, "Direct access to this service is not allowed.");
            return;
        }

        if (!timingSafeEquals(gatewaySecret, properties.getSecret())) {
            log.warn("Rejected request to '{}': invalid {} value", path, GATEWAY_SECRET_HEADER);
            sendForbidden(response, "Direct access to this service is not allowed.");
            return;
        }

        // 2. Validate that the gateway already authenticated the user ----------
        String user = request.getHeader(USER_HEADER);

        if (user == null || user.isBlank()) {
            log.warn("Rejected request to '{}': missing {} header", path, USER_HEADER);
            sendForbidden(response, "Missing user identity — ensure the request passes through the API-Gateway.");
            return;
        }

        // All checks passed, continue the filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Paths that are allowed to bypass gateway-origin checks.
     * Override or extend in each microservice if needed.
     */
    protected boolean isPublicPath(String path) {
        return path.startsWith("/actuator")
                || path.startsWith("/auth/login")
                || path.startsWith("/auth/register");
    }

    /** Writes a 403 response with a plain-text body. */
    private void sendForbidden(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"" + message + "\"}");
    }

    /**
     * Constant-time string comparison to prevent timing-based secret leakage.
     * Returns {@code true} only when both strings are identical.
     */
    private boolean timingSafeEquals(String a, String b) {
        if (a == null || b == null) return false;
 
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
 
        return MessageDigest.isEqual(aBytes, bBytes);
    }
}