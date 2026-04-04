package uptc.edu.co.api_gateway.filters;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import co.edu.uptc.shared.security.JwtScopeExtractor;
import co.edu.uptc.shared.security.RoleScopeCatalog;
import co.edu.uptc.shared.security.ScopeAuthorizationMiddleware;
import javax.crypto.SecretKey;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthFilter implements GlobalFilter, Ordered {

    private final ScopeAuthorizationMiddleware scopeAuthorizationMiddleware = new ScopeAuthorizationMiddleware();
    private final SecretKey key;

    public AuthFilter(@Value("${jwt.secret}") String secretBase64) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretBase64));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();
        HttpMethod method = exchange.getRequest().getMethod();

        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest()
                                    .getHeaders()
                                    .getFirst("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException ex) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        Set<String> scopes = JwtScopeExtractor.extractScopes(claims);
        Set<String> requiredScopes = requiredScopes(method, path, exchange);

        if (!scopeAuthorizationMiddleware.isAllowed(scopes, requiredScopes)) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    private boolean isPublicPath(String path) {
        return path.equals("/ms-auth/auth/login")
                || path.equals("/ms-auth/auth/register")
                || path.startsWith("/ms-auth/actuator");
    }

    private Set<String> requiredScopes(HttpMethod method, String path, ServerWebExchange exchange) {
        if (isServicePath(path, "/ms-contracts")) {
            if (method == HttpMethod.POST) {
                return Set.of(RoleScopeCatalog.CREATE_CONTRACT);
            }

            if (method == HttpMethod.PUT || method == HttpMethod.PATCH) {
                return Set.of(RoleScopeCatalog.UPDATE_CONTRACT);
            }

            if (method == HttpMethod.GET) {
                return readContractScopes(exchange);
            }
        }

        if (isServicePath(path, "/ms-suppliers")) {
            if (method == HttpMethod.POST) {
                return Set.of(RoleScopeCatalog.CREATE_SUPPLIER);
            }

            if (method == HttpMethod.PUT || method == HttpMethod.PATCH) {
                return Set.of(RoleScopeCatalog.UPDATE_SUPPLIER);
            }

            if (method == HttpMethod.GET) {
                return Set.of(RoleScopeCatalog.VIEW_SUPPLIERS);
            }
        }

        if (isServicePath(path, "/ms-audit") && method == HttpMethod.GET) {
            return Set.of(RoleScopeCatalog.VIEW_AUDIT);
        }

        return Set.of();
    }

    private Set<String> readContractScopes(ServerWebExchange exchange) {
        if (hasByIdQuery(exchange)) {
            return Set.of(RoleScopeCatalog.VIEW_CONTRACTS_BY_ID);
        }

        return Set.of(RoleScopeCatalog.VIEW_CONTRACTS);
    }

    private boolean hasByIdQuery(ServerWebExchange exchange) {
        return exchange.getRequest().getQueryParams().containsKey("contractId")
                || exchange.getRequest().getQueryParams().containsKey("id");
    }

    private boolean isServicePath(String path, String servicePrefix) {
        return path.equals(servicePrefix) || path.startsWith(servicePrefix + "/");
    }

    @Override
    public int getOrder() {
        return -1;
    }
}