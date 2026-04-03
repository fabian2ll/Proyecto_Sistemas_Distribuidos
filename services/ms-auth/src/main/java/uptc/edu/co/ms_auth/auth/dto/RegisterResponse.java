package uptc.edu.co.ms_auth.auth.dto;

import java.util.List;

public class RegisterResponse {

    private Long id;
    private String username;
    private boolean active;
    private List<String> roles;

    public RegisterResponse() {
    }

    public RegisterResponse(Long id, String username, boolean active, List<String> roles) {
        this.id = id;
        this.username = username;
        this.active = active;
        this.roles = roles;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public boolean isActive() {
        return active;
    }

    public List<String> getRoles() {
        return roles;
    }
}
