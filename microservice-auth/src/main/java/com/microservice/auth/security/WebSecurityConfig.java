package com.microservice.auth.security;


import com.microservice.auth.security.jwt.AuthEntryPointJwt;
import com.microservice.auth.security.jwt.AuthTokenFilter;
import com.microservice.auth.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;



@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
  @Autowired
  UserDetailsServiceImpl userDetailsService;

  @Autowired
  private AuthEntryPointJwt unauthorizedHandler;



  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }


  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(csrf -> csrf.disable())
            .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(new AntPathRequestMatcher("/api/auth/**")).permitAll() // Endpoints públicos
                    .requestMatchers(new AntPathRequestMatcher("/api/test/user")).hasAnyRole("USER", "ADMIN", "MODERATOR")
                    .requestMatchers(new AntPathRequestMatcher("/api/test/moderator")).hasAnyAuthority("ROLE_MODERATOR")
                    .requestMatchers(new AntPathRequestMatcher("/api/test/admin")).hasRole("ADMIN")
                    .requestMatchers(new AntPathRequestMatcher("/api/test/delete"))
                    .access((authentication, context) -> new AuthorizationDecision(
                            hasRole(authentication.get(), "MODERATOR") &&
                                    hasAuthority(authentication.get(), "ROLE_UPDATE")))
                    .anyRequest().authenticated());

    http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  private boolean hasRole(Authentication authentication, String role) {
    return authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .anyMatch(auth -> auth.equals("ROLE_" + role));
  }

  private boolean hasAuthority(Authentication authentication, String authority) {
    return authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .anyMatch(auth -> auth.equals(authority));
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
  }
}
