package rbpo.task2.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import rbpo.task2.dto.AuthRequest;
import rbpo.task2.dto.AuthResponse;
import rbpo.task2.dto.RefreshRequest;
import rbpo.task2.dto.Registration;
import rbpo.task2.service.AuthService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService service;
    public AuthController(AuthService service) { this.service = service; }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public AuthResponse register(@Valid @RequestBody Registration request) { return service.register(request); }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody AuthRequest request) { return service.login(request); }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody RefreshRequest request) { return service.refresh(request.refreshToken()); }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestBody RefreshRequest request) { service.logout(request.refreshToken()); }
}
