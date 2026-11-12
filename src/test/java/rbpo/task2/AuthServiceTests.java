package rbpo.task2;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;
import rbpo.task2.dto.AuthResponse;
import rbpo.task2.model.SessionStatus;
import rbpo.task2.model.UserSession;
import rbpo.task2.repository.UserRepository;
import rbpo.task2.model.User;
import rbpo.task2.service.RegistrationService;
import rbpo.task2.repository.UserSessionRepository;
import rbpo.task2.security.JwtService;
import rbpo.task2.service.AuthService;
import java.time.Instant;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthServiceTests {
    @Test
    void refreshИспользуетсяТолькоОдинРаз() {
        UserRepository users = mock(UserRepository.class);
        UserSessionRepository sessions = mock(UserSessionRepository.class);
        JwtService jwt = new JwtService("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=");
        AuthService service = new AuthService(users, sessions, mock(RegistrationService.class), new BCryptPasswordEncoder(), jwt);
        UserSession old = new UserSession();
        old.setUsername("ivan");
        old.setDeviceId("phone");
        old.setStatus(SessionStatus.ACTIVE);
        old.setRefreshTokenExpiry(Instant.now().plusSeconds(60));
        old.setRefreshToken(jwt.create("ivan", "refresh", old.getRefreshTokenExpiry()));
        User user = new User();
        when(users.findByEmail("ivan")).thenReturn(Optional.of(user));
        when(sessions.findByRefreshToken(old.getRefreshToken())).thenReturn(Optional.of(old));
        when(sessions.save(any(UserSession.class))).thenAnswer(call -> call.getArgument(0));

        AuthResponse result = service.refresh(old.getRefreshToken());
        assertEquals(SessionStatus.USED, old.getStatus());
        assertNotEquals(old.getRefreshToken(), result.refreshToken());
        assertThrows(ResponseStatusException.class, () -> service.refresh(old.getRefreshToken()));
    }
}
