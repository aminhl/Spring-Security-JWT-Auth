package org.nexthope.springsecurity_jwt_auth.configuration;

import lombok.RequiredArgsConstructor;
import org.nexthope.springsecurity_jwt_auth.user.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfiguration {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findUserByEmail(username)
                .orElse(null);
    }

}
