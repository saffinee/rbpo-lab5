package rbpo.task2.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false)
    private String username;
    private String deviceId;
    @Column(nullable = false, columnDefinition = "text")
    private String accessToken;
    @Column(nullable = false, unique = true, columnDefinition = "text")
    private String refreshToken;
    @Column(nullable = false)
    private Instant accessTokenExpiry;
    @Column(nullable = false)
    private Instant refreshTokenExpiry;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SessionStatus status;

    public UUID getId() { return id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    public Instant getAccessTokenExpiry() { return accessTokenExpiry; }
    public void setAccessTokenExpiry(Instant accessTokenExpiry) { this.accessTokenExpiry = accessTokenExpiry; }
    public Instant getRefreshTokenExpiry() { return refreshTokenExpiry; }
    public void setRefreshTokenExpiry(Instant refreshTokenExpiry) { this.refreshTokenExpiry = refreshTokenExpiry; }
    public SessionStatus getStatus() { return status; }
    public void setStatus(SessionStatus status) { this.status = status; }
}
