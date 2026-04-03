package uptc.edu.co.api_gateway.filters;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
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

        Set<String> scopes = extractScopes(claims.get("scopes"));
        String requiredScope = requiredScope(method, path);

        if (requiredScope != null && !scopes.contains(requiredScope)) {
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

    private String requiredScope(HttpMethod method, String path) {
        if (method == HttpMethod.POST && path.startsWith("/ms-contracts/")) {
            return "create:contract";
        }

        if (method == HttpMethod.GET && path.startsWith("/ms-audit/")) {
            return "view:audit";
        }

        return null;
    }

    private Set<String> extractScopes(Object rawScopes) {
        if (!(rawScopes instanceof Collection<?> collection)) {
            return Set.of();
        }

        return collection.stream()
                .map(Object::toString)
                .collect(Collectors.toCollection(HashSet::new));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}