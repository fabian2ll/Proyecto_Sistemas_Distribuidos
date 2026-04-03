package uptc.edu.co.ms_auth.auth.dto;

import java.util.List;

public class AuthResponse {

    private String token;
    private String tokenType;
    private long expiresIn;
    private List<String> scopes;

    public AuthResponse() {
    }

    public AuthResponse(String token, String tokenType, long expiresIn, List<String> scopes) {
        this.token = token;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.scopes = scopes;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }
}
