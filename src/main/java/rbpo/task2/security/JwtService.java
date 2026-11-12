package rbpo.task2.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    private final SecretKey key;

    public JwtService(@Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public String create(String username, String type, Instant expiry) {
        return Jwts.builder().subject(username).id(UUID.randomUUID().toString())
                .claim("type", type).issuedAt(new Date()).expiration(Date.from(expiry))
                .signWith(key, Jwts.SIG.HS256).compact();
    }

    public String username(String token, String type) {
        var signed = Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
        if (!"HS256".equals(signed.getHeader().getAlgorithm())) {
            throw new IllegalArgumentException("Неверный алгоритм токена");
        }
        Claims claims = signed.getPayload();
        if (!type.equals(claims.get("type", String.class)) || claims.getSubject() == null
                || claims.getExpiration() == null || claims.getId() == null) {
            throw new IllegalArgumentException("Неверный токен");
        }
        return claims.getSubject();
    }
}
