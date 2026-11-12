package rbpo.task2;

import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import rbpo.task2.security.JwtService;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTests {
    private final JwtService jwt = new JwtService("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=");

    @Test
    void проверяетТипПодписьИВремя() {
        String token = jwt.create("ivan", "access", Instant.now().plusSeconds(60));
        assertEquals("ivan", jwt.username(token, "access"));
        assertThrows(IllegalArgumentException.class, () -> jwt.username(token, "refresh"));
        assertThrows(JwtException.class, () -> jwt.username(token + "x", "access"));
        String expired = jwt.create("ivan", "access", Instant.now().minusSeconds(60));
        assertThrows(JwtException.class, () -> jwt.username(expired, "access"));
    }
}
