package com.securenote.securenotes.Configurations;

import com.securenote.securenotes.Entities.Role;
import com.securenote.securenotes.Entities.User;
import com.securenote.securenotes.Entities.UserRoles;
import com.securenote.securenotes.Repository.RoleRepository;
import com.securenote.securenotes.Repository.UserRepository;
import com.securenote.securenotes.Security.jwt.AuthExceptionEntryPointJwt;
import com.securenote.securenotes.Security.jwt.AuthTokenFilter;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import java.time.LocalDate;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true ,
        securedEnabled = true,
        jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    @Lazy
    private OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    private final AuthenticationConfiguration authConfiguration;

    private final AuthExceptionEntryPointJwt authExceptionEntryPointJwt;

    @Bean
    public AuthTokenFilter authTokenFilter(){
        return new AuthTokenFilter();
    }
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authConfiguration.getAuthenticationManager();
    }

    @Bean
    public GoogleAuthenticator googleAuthenticator() {
        return new GoogleAuthenticator(); // You can pass constructor arguments if needed
    }

        @Bean
        SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
                throws Exception {
            http.authorizeHttpRequests((requests) -> requests
                    .requestMatchers("/api/admin/**").hasRole("ADMIN")
                    .requestMatchers("/api/auth/public/**" ,
                            "/api/csrf-token").permitAll()
                            .requestMatchers("/oauth2/**").permitAll()
                    .anyRequest()
                    .authenticated())
                    .oauth2Login(oauth -> {
                    oauth.successHandler(oAuth2LoginSuccessHandler);
                    });
//            http.csrf(AbstractHttpConfigurer::disable);
            //http.formLogin(withDefaults());
            // enabling csrf token
            http.csrf(
                    csrf -> csrf.csrfTokenRepository(
                            CookieCsrfTokenRepository.withHttpOnlyFalse()
                    )
                            .ignoringRequestMatchers("/api/auth/public/**")
            );

            http.cors(
                    cors -> cors.configurationSource(corsConfigurationSource())
            );
//            http.addFilterBefore(customLoggingFilter,
//                    UsernamePasswordAuthenticationFilter.class);
//            http.addFilterAfter(requestValidationFilter,
//                    CustomLoggingFilter.class);
            http.exceptionHandling(
                    exception -> exception.authenticationEntryPoint(
                            authExceptionEntryPointJwt
                    )
            );
                    http.addFilterBefore(
                            authTokenFilter(), UsernamePasswordAuthenticationFilter.class
                    );
            http.httpBasic(Customizer.withDefaults());

            return http.build();
        }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        // Allow specific origins
        corsConfig.setAllowedOrigins(Arrays.asList("http://localhost:3000"));

        // Allow specific HTTP methods
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // Allow specific headers
        corsConfig.setAllowedHeaders(Arrays.asList("*"));
        // Allow credentials (cookies, authorization headers)
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(3600L);
        // Define allowed paths (for all paths use "/**")
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig); // Apply to all endpoints
        return source;
    }

    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository,
                                      UserRepository userRepository,
                                      PasswordEncoder passwordEncoder) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(UserRoles.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(UserRoles.ROLE_USER)));

            Role adminRole = roleRepository.findByRoleName(UserRoles.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(UserRoles.ROLE_ADMIN)));

            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1",
                        "user1@example.com",
                        passwordEncoder.encode("password1")
                        );
                user1.setAccountNonLocked(false);
                user1.setAccountNonExpired(true);
                user1.setCredentialsNonExpired(true);
                user1.setEnabled(true);
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user1.setTwoFactorEnabled(false);
                user1.setSignUpMethod("email");
                user1.setRole(userRole);
                userRepository.save(user1);
            }

            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin",
                        "admin@example.com",
                        passwordEncoder.encode("adminPass") );
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
    }


}
