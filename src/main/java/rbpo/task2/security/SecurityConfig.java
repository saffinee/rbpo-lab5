package rbpo.task2.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import rbpo.task2.repository.UserRepository;
import java.io.IOException;
import java.util.Locale;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean
    UserDetailsService userDetailsService(UserRepository repository) {
        return email -> {
            var user = repository.findByEmail(email.trim().toLowerCase(Locale.ROOT))
                    .orElseThrow(() -> new UsernameNotFoundException("Неверные учётные данные"));
            return User.withUsername(user.getEmail()).password(user.getPasswordHash())
                    .roles(user.getRole()).disabled(!user.isEnabled()).accountLocked(user.isLocked()).build();
        };
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService jwt, UserDetailsService users) throws Exception {
        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected boolean shouldNotFilter(HttpServletRequest request) {
                return request.getServletPath().startsWith("/api/auth/");
            }
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                    throws ServletException, IOException {
                String header = request.getHeader("Authorization");
                if (header != null) {
                    try {
                        if (!header.startsWith("Bearer ")) throw new IllegalArgumentException();
                        UserDetails user = users.loadUserByUsername(jwt.username(header.substring(7), "access"));
                        if (!user.isEnabled() || !user.isAccountNonLocked()) throw new IllegalArgumentException();
                        SecurityContextHolder.getContext().setAuthentication(
                                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
                    } catch (JwtException | IllegalArgumentException | UsernameNotFoundException e) {
                        response.sendError(401);
                        return;
                    }
                }
                chain.doFilter(request, response);
            }
        };
        return http.csrf(c -> c.disable()) //токены передаются явно, не в cookie
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(c -> c.disable())
                .exceptionHandling(c -> c.authenticationEntryPoint((request, response, exception) -> response.sendError(401))
                        .accessDeniedHandler(new SecurityErrors()))
                .authorizeHttpRequests(c -> c
                        .requestMatchers(HttpMethod.POST, "/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/logout").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().denyAll())
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class).build();
    }
}
