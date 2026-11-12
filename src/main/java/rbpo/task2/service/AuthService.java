package rbpo.task2.service;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import rbpo.task2.dto.AuthRequest;
import rbpo.task2.dto.AuthResponse;
import rbpo.task2.dto.Registration;
import rbpo.task2.model.SessionStatus;
import rbpo.task2.model.User;
import rbpo.task2.model.UserSession;
import rbpo.task2.repository.UserRepository;
import rbpo.task2.repository.UserSessionRepository;
import rbpo.task2.security.JwtService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

@Service
public class AuthService {
    private final UserRepository users;
    private final UserSessionRepository sessions;
    private final RegistrationService registration;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwt;

    public AuthService(UserRepository users, UserSessionRepository sessions, RegistrationService registration,
                       PasswordEncoder passwordEncoder, JwtService jwt) {
        this.users = users;
        this.sessions = sessions;
        this.registration = registration;
        this.passwordEncoder = passwordEncoder;
        this.jwt = jwt;
    }

    @Transactional
    public AuthResponse register(Registration request) {
        User user = registration.register(request);
        return createSession(user.getEmail(), request.deviceId());
    }

    @Transactional
    public AuthResponse login(AuthRequest request) {
        if (request.email() == null || request.password() == null) throw unauthorized();
        User user = users.findByEmail(request.email().trim().toLowerCase(Locale.ROOT)).orElseThrow(this::unauthorized);
        if (!user.isEnabled() || user.isLocked() || !passwordEncoder.matches(request.password(), user.getPasswordHash())) throw unauthorized();
        return createSession(user.getEmail(), request.deviceId());
    }

    @Transactional
    public AuthResponse refresh(String token) {
        UserSession session = activeSession(token);
        session.setStatus(SessionStatus.USED);
        sessions.save(session);
        return createSession(session.getUsername(), session.getDeviceId());
    }

    @Transactional
    public void logout(String token) {
        UserSession session = activeSession(token);
        session.setStatus(SessionStatus.REVOKED);
        sessions.save(session);
    }

    private UserSession activeSession(String token) {
        try {
            String username = jwt.username(token, "refresh");
            UserSession session = sessions.findByRefreshToken(token).orElseThrow(this::unauthorized);
            User user = users.findByEmail(username).orElseThrow(this::unauthorized);
            if (session.getStatus() != SessionStatus.ACTIVE || !session.getUsername().equals(username)
                    || !session.getRefreshTokenExpiry().isAfter(Instant.now()) || !user.isEnabled() || user.isLocked()) {
                throw unauthorized();
            }
            return session;
        } catch (JwtException | IllegalArgumentException e) {
            throw unauthorized();
        }
    }

    private AuthResponse createSession(String username, String deviceId) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant accessExpiry = now.plus(15, ChronoUnit.MINUTES);
        Instant refreshExpiry = now.plus(7, ChronoUnit.DAYS);
        UserSession session = new UserSession();
        session.setUsername(username);
        session.setDeviceId(deviceId);
        session.setAccessTokenExpiry(accessExpiry);
        session.setRefreshTokenExpiry(refreshExpiry);
        session.setAccessToken(jwt.create(username, "access", accessExpiry));
        session.setRefreshToken(jwt.create(username, "refresh", refreshExpiry));
        session.setStatus(SessionStatus.ACTIVE);
        sessions.save(session);
        return new AuthResponse(username, session.getAccessToken(), session.getRefreshToken());
    }

    private ResponseStatusException unauthorized() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Неверный логин, пароль или токен");
    }
}
