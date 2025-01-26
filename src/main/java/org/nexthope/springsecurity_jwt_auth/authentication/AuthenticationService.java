package org.nexthope.springsecurity_jwt_auth.authentication;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nexthope.springsecurity_jwt_auth.configuration.JwtService;
import org.nexthope.springsecurity_jwt_auth.exception.UserFoundException;
import org.nexthope.springsecurity_jwt_auth.exception.UserNotFoundException;
import org.nexthope.springsecurity_jwt_auth.user.User;
import org.nexthope.springsecurity_jwt_auth.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static org.nexthope.springsecurity_jwt_auth.user.Role.CLIENT;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final JwtService jwtService;

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(final RegisterRequest registerRequest) throws AuthenticationException, UserFoundException {
        Optional<User> userByEmail = userRepository.findUserByEmail(registerRequest.email());
        if (userByEmail.isEmpty()) {
            User user = User.builder()
                    .firstname(registerRequest.firstname())
                    .lastname(registerRequest.lastname())
                    .email(registerRequest.email())
                    .password(registerRequest.password())
                    .role(CLIENT)
                    .build();
            userRepository.save(user);
            log.info("User with email {} successfully registered.", registerRequest.email());
            String accessToken = jwtService.generateAccessToken(user);
            return new AuthenticationResponse(accessToken);
        } else {
            log.error("Registration failed: Email {} is already in use.", registerRequest.email());
            throw new UserFoundException("Registration failed: Email " + registerRequest.email() + " is already in use.");
        }
    }

    public AuthenticationResponse authenticate(final AuthenticationRequest authenticationRequest) throws AuthenticationException, UserNotFoundException {
        Optional<User> userByEmail = userRepository.findUserByEmail(authenticationRequest.email());
        if (userByEmail.isPresent()) {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authenticationRequest.email(),
                            authenticationRequest.password()
                    )
            );
            String accessToken = jwtService.generateAccessToken(userByEmail.get());
            return new AuthenticationResponse(accessToken);
        } else {
            log.warn("Authentication failed: No user found with email: {}", authenticationRequest.email());
            throw new UserNotFoundException("Authentication failed: No user found with email: " + authenticationRequest.email()) {};
        }
    }
}
