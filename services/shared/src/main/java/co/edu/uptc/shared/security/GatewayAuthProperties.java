package co.edu.uptc.shared.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds the property {@code gateway.secret} from application.yml / environment.
 *
 * <pre>
 * gateway:
 *   secret: ${GATEWAY_SECRET}   # same value set in the API-Gateway
 * </pre>
 */
@ConfigurationProperties(prefix = "gateway")
public class GatewayAuthProperties {

    /** Shared secret that the API-Gateway injects as {@code X-Gateway-Secret}. */
    private String secret;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
}