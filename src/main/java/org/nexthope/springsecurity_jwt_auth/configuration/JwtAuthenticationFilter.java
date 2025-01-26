package org.nexthope.springsecurity_jwt_auth.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT authentication filter that intercepts incoming HTTP requests to validate JWT tokens.
 * <p>
 * This filter extends {@link OncePerRequestFilter} to ensure that authentication is applied
 * once per request. It checks the presence and validity of a JWT token in the request's
 * Authorization header and sets the security context accordingly.
 * </p>
*/
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    /**
     * Filters incoming HTTP requests to validate and authenticate JWT tokens.
     * <p>
     * This method intercepts each request and checks for the presence of a valid JWT token
     * in the Authorization header. If a valid token is found, it sets the authentication in the security context.
     * </p>
    */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI();
        log.info("Processing request for URI: {}", requestUri);

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Authorization header is missing or invalid for request URI: {}", requestUri);
            filterChain.doFilter(request, response);
            return;
        }
        String accessToken = authHeader.substring(7);
        String userEmail = jwtService.extractUsername(accessToken);
        if (userEmail == null) {
            log.warn("Failed to extract username from token for request URI: {}", requestUri);
        } else {
            log.info("Extracted username: {} from token for request URI: {}", userEmail, requestUri);
        }
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails user = userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(accessToken, user)) {
                log.info("Token is valid for user: {}", userEmail);
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                log.info("Authentication set successfully for user: {}", userEmail);
            } else {
                log.warn("Invalid token for user: {}", userEmail);
            }
        }
        log.info("Proceeding with the filter chain for request URI: {}", requestUri);
        filterChain.doFilter(request, response);
    }

}
