package rbpo.task2.repository;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import rbpo.task2.model.UserSession;
import java.util.Optional;
import java.util.UUID;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE) //один refresh нельзя использовать одновременно два раза
    Optional<UserSession> findByRefreshToken(String refreshToken);
}
